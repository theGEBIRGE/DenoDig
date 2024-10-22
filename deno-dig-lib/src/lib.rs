use eszip::EszipV2;
use futures::io::BufReader;
use futures::AsyncReadExt;
use object::coff::CoffHeader;
use object::read::pe::{
    ImageNtHeaders, ResourceDirectory, ResourceDirectoryEntryData, ResourceDirectoryTable,
    ResourceNameOrId,
};
use object::LittleEndian as LE;
use object::{pe, BinaryFormat, Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::{Cursor, Write};
use std::path::Path;
use std::process;
use wasm_bindgen::prelude::*;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MAGIC_TRAILER: &[u8; 8] = b"d3n0l4nd";
const TRAILER_SIZE: usize = size_of::<Trailer>() + MAGIC_TRAILER.len();
const VERSION_UNO_OFFSET: usize = 16;
const VERSION_DOS_OFFSET: usize = 24;
const VERSION_TRES_OFFSET: usize = TRAILER_SIZE;

#[derive(Debug, Serialize, Deserialize)]
pub enum VfsEntry {
    Dir(VirtualDirectory),
    File(VirtualFile),
    Symlink(VirtualSymlink),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtualDirectory {
    pub name: String,
    pub entries: Vec<VfsEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtualFile {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtualSymlink {
    pub name: String,
    pub dest_parts: Vec<String>,
}

#[derive(Debug)]
pub struct Trailer {
    eszip_pos: u64,
    metadata_pos: u64,
    npm_vfs_pos: u64,
    npm_files_pos: u64,
}

impl Trailer {
    pub fn parse(trailer: &[u8]) -> Result<Option<Trailer>, Box<dyn Error>> {
        let (magic_trailer, rest) = trailer.split_at(8);

        if magic_trailer != MAGIC_TRAILER {
            return Ok(None);
        }

        let (eszip_archive_pos, rest) = rest.split_at(8);
        let (metadata_pos, rest) = rest.split_at(8);
        let (npm_vfs_pos, npm_files_pos) = rest.split_at(8);

        let eszip_pos = u64_from_bytes(eszip_archive_pos)?;
        let metadata_pos = u64_from_bytes(metadata_pos)?;
        let npm_vfs_pos = u64_from_bytes(npm_vfs_pos)?;
        let npm_files_pos = u64_from_bytes(npm_files_pos)?;

        Ok(Some(Trailer {
            eszip_pos,
            metadata_pos,
            npm_vfs_pos,
            npm_files_pos,
        }))
    }
    pub fn metadata_len(&self) -> u64 {
        self.npm_vfs_pos - self.metadata_pos
    }

    pub fn npm_vfs_len(&self) -> u64 {
        self.npm_files_pos - self.npm_vfs_pos
    }
}

#[wasm_bindgen]
pub async fn process_binary_file(binary_data: Vec<u8>) -> Option<Vec<u8>> {
    let mut zip_buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(&mut zip_buffer));

    let options: SimpleFileOptions = SimpleFileOptions::default()
        .compression_level(None)
        .compression_method(CompressionMethod::Stored);

    if check_version(&binary_data, VERSION_UNO_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.6.0  <1.7.0");
        let bundle_pos_arr: &[u8; 8] = &binary_data[(binary_data.len() - 8)..].try_into().unwrap();
        let bundle_pos = u64::from_be_bytes(*bundle_pos_arr);

        let bundle = &binary_data[bundle_pos as usize..&binary_data.len() - VERSION_UNO_OFFSET];

        zip.start_file_from_path("bundle.js", options)
            .expect("TODO: panic message");
        zip.write_all(bundle).unwrap();
    } else if check_version(&binary_data, VERSION_DOS_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.7.0  <1.33.3");
        let pointers: &[u8; 16] = &binary_data[(binary_data.len() - 16)..].try_into().unwrap();
        let (bundle_pos_arr, metadata_pos_arr) = pointers.split_at(8);

        let bundle_pos_arr: &[u8; 8] = bundle_pos_arr.try_into().unwrap();
        let metadata_pos_arr: &[u8; 8] = metadata_pos_arr.try_into().unwrap();

        let bundle_pos = u64::from_be_bytes(*bundle_pos_arr);
        let metadata_pos = u64::from_be_bytes(*metadata_pos_arr);

        let bundle = &binary_data[bundle_pos as usize..metadata_pos as usize];
        let metadata = &binary_data[metadata_pos as usize..binary_data.len() - VERSION_DOS_OFFSET];

        zip.start_file_from_path("bundle.js", options)
            .expect("TODO: panic message");
        zip.write_all(bundle).unwrap();
        zip.start_file_from_path("metadata.js", options)
            .expect("TODO: panic message");
        zip.write_all(metadata).unwrap();
    } else if check_version(&binary_data, VERSION_TRES_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.33.3  <1.46");
        let trailer_data = &binary_data[binary_data.len() - TRAILER_SIZE..];

        let trailer = Trailer::parse(trailer_data)
            .expect("[!] Failed to parse Trailer")
            .unwrap();
        let eszip_bytes = &binary_data[trailer.eszip_pos as usize..];

        let bufreader = BufReader::new(eszip_bytes);
        let (eszip, loader) = EszipV2::parse(bufreader).await.unwrap();

        let bufreader = loader.await.unwrap();

        let mut metadata = String::new();

        bufreader
            .take(trailer.metadata_len())
            .read_to_string(&mut metadata)
            .await
            .unwrap();

        zip.start_file_from_path("metadata.js", options)
            .expect("[!] Failed to extract metadata");
        zip.write_all(metadata.as_bytes()).unwrap();

        extract_modules(eszip, &mut zip, options)
            .await
            .expect("[!] Failed to extract modules");
        extract_packages(&trailer, &binary_data, &mut zip, options)
            .expect("[!] Failed to extract packages");
    } else {
        println!("[*] Binary compiled with Deno >= 1.46");

        let file = object::File::parse(&*binary_data).expect("[!] Failed to parse input file");
        let data;

        match file.format() {
            BinaryFormat::Elf => {
                println!("[*] ELF file detected");

                let offset_arr: &[u8; 4] =
                    &binary_data[(binary_data.len() - 4)..].try_into().unwrap();
                let negative_offset = u32::from_le_bytes(*offset_arr);

                let offset = binary_data.len() - negative_offset as usize;

                data = Vec::from(&binary_data[offset..binary_data.len() - 12]);
            }
            BinaryFormat::MachO => {
                println!("[*] Mach-O file detected");
                let section = file.section_by_name("d3n0l4nd").unwrap();

                println!("[*] Found section '{}'", section.name().unwrap());

                data = Vec::from(section.data().unwrap());
            }
            BinaryFormat::Pe => {
                println!("[*] PE file detected");

                let dos_header = pe::ImageDosHeader::parse(&*binary_data)
                    .expect("[!] Failed to parse Dos header");
                let mut offset = dos_header.nt_headers_offset().into();
                let (nt_headers, data_directories) =
                    pe::ImageNtHeaders64::parse(&*binary_data, &mut offset)
                        .expect("[!] Failed to parse Data directories");

                let header = nt_headers.file_header();
                let sections = header.sections(&*binary_data, offset).unwrap();

                let mut section_rva = 0;
                let mut section_raw_offset = 0;

                let mut found_section = false;

                for section in sections.iter() {
                    if let Ok(section_name) = std::str::from_utf8(&section.name) {
                        if section_name.starts_with(".pedata") {
                            println!(
                                "[*] Found '.pedata' section with virtual address {} and raw offset {}",
                                section.virtual_address.get(LE),
                                section.pointer_to_raw_data.get(LE)
                            );
                            section_rva = section.virtual_address.get(LE);
                            section_raw_offset = section.pointer_to_raw_data.get(LE);
                            found_section = true;
                            break;
                        }
                    }
                }

                if !found_section {
                    eprintln!("[!] .pedata section not found");
                    process::exit(1);
                }

                let directory = data_directories
                    .resource_directory(&*binary_data, &sections)
                    .unwrap()
                    .unwrap();

                let root_table = directory.root().unwrap();

                let (resource_rva, resource_size) =
                    get_deno_resource(directory, root_table).unwrap();

                // We must translate virtual addresses to actual file offsets in order get the correct slice.
                // Formula: (RVA of the resource) - (virtual address of .pedata) + (raw offset of .pedata)
                let start = resource_rva - section_rva + section_raw_offset;

                data = Vec::from(&binary_data[start as usize..(start + resource_size) as usize]);
            }
            _ => {
                eprintln!("[!] Unsupported binary format");
                process::exit(1);
            }
        }

        let trailer = Trailer::parse(&data[0..TRAILER_SIZE])
            .expect("[!] Failed to parse Trailer")
            .unwrap();

        let without_trailer = &data[TRAILER_SIZE..];

        let bufreader = BufReader::new(without_trailer);
        let (eszip, loader) = EszipV2::parse(bufreader).await.unwrap();
        let bufreader = loader.await.unwrap();

        let mut metadata = String::new();

        bufreader
            .take(trailer.metadata_len())
            .read_to_string(&mut metadata)
            .await
            .unwrap();

        zip.start_file_from_path("metadata.js", options)
            .expect("TODO: panic message");
        zip.write_all(metadata.as_bytes()).unwrap();

        extract_modules(eszip, &mut zip, options)
            .await
            .expect("[!] Failed to extract modules");
        extract_packages(&trailer, &without_trailer, &mut zip, options)
            .expect("[!] Failed to extract modules");
    }

    zip.finish().unwrap();

    Some(zip_buffer)
}

async fn extract_modules(
    eszip: EszipV2,
    zip: &mut ZipWriter<Cursor<&mut Vec<u8>>>,
    options: SimpleFileOptions,
) -> std::io::Result<()> {
    for specifier in eszip.specifiers().iter() {
        if let Some(module) = eszip.get_module(specifier) {
            println!("[+] Handling module '{}'", specifier);

            let source = module.source().await.unwrap();

            // We don't have to worry about zip slips, right?
            // https://docs.rs/zip/2.2.0/zip/write/struct.ZipWriter.html#method.start_file_from_path
            zip.start_file_from_path(specifier, options)
                .expect("TODO: panic message");

            zip.write_all(&source)?;
        } else {
            if !specifier.starts_with("npm") {
                eprintln!("[!] Failed to get module for {}", specifier);
            }
        }
    }
    Ok(())
}

pub fn extract_packages(
    trailer: &Trailer,
    without_trailer: &[u8],
    mut zip: &mut ZipWriter<Cursor<&mut Vec<u8>>>,
    options: SimpleFileOptions,
) -> Result<(), Box<dyn Error>> {
    let vfs_data = &without_trailer[trailer.npm_vfs_pos as usize..trailer.npm_files_pos as usize];

    // If no packages are included, the JSON will be `null`.
    let vfs_root: Option<VirtualDirectory> = serde_json::from_slice(vfs_data)?;

    if let Some(virtual_directory) = vfs_root {
        let npm_files = &without_trailer[trailer.npm_files_pos as usize..];

        traverse_directories(
            virtual_directory,
            npm_files,
            Path::new(""),
            &mut zip,
            options,
        )?;
    };

    Ok(())
}

pub fn traverse_directories(
    dir: VirtualDirectory,
    npm_files: &[u8],
    parent_path: &Path,
    zip: &mut ZipWriter<Cursor<&mut Vec<u8>>>,
    options: SimpleFileOptions,
) -> Result<(), Box<dyn Error>> {
    let current_path = parent_path.join(&dir.name);

    for entry in dir.entries {
        match entry {
            VfsEntry::File(file) => {
                let offset = file.offset;
                let file_bytes = &npm_files[offset as usize..(offset + file.len) as usize];
                let file_path = current_path.join(file.name);

                // We don't have to worry about zip slips, right?
                // https://docs.rs/zip/2.2.0/zip/write/struct.ZipWriter.html#method.start_file_from_path
                zip.start_file_from_path(&file_path, options)
                    .expect("TODO: panic message");
                zip.write_all(file_bytes)?;
            }
            VfsEntry::Dir(sub_dir) => {
                traverse_directories(sub_dir, npm_files, &current_path, zip, options)?;
            }
            VfsEntry::Symlink(_symlink) => {
                panic!("[!] Can't handle symlinks yet")
            }
        }
    }

    Ok(())
}

fn get_deno_resource(
    directory: ResourceDirectory<'_>,
    root_table: ResourceDirectoryTable<'_>,
) -> Option<(u32, u32)> {
    const RT_RCDATA: u32 = 10;
    let mut size: u32 = 0;
    let mut virtual_address: u32 = 0;

    // We start from the root table and collect every entry that's of type RT_RCDATA,
    // see https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
    // Here are more infos about the structure of those tables:
    // https://lief.re/doc/stable/tutorials/07_pe_resource.html#resource-structure
    let rcdata_tables: Vec<_> = root_table
        .entries
        .iter()
        .filter(|entry| entry.name_or_id.get(LE) == RT_RCDATA)
        .filter_map(|entry| match entry.data(directory) {
            Ok(ResourceDirectoryEntryData::Table(sub_table)) => Some(sub_table),
            _ => None,
        })
        .collect();

    // We iterate through every table and check for the 'D3N0L4ND' entry, which contains another table.
    // *That* table contains (presumably) only one resource data entry, which finally gives us
    // the relative virtual address (RVA) and size of the blob we're looking for.
    rcdata_tables.iter().for_each(|table| {
        table
            .entries
            .iter()
            .for_each(|entry| match entry.name_or_id() {
                ResourceNameOrId::Name(name) => {
                    if let Ok(name) = name.to_string_lossy(directory) {
                        if name.eq("D3N0L4ND") {
                            println!("[*] Found Deno resource '{}'", name,);
                            let resource_data = entry.data(directory).unwrap();
                            let resource_table = resource_data.table().unwrap();

                            for lower_entry in resource_table.entries {
                                if let Ok(ResourceDirectoryEntryData::Data(data_entry)) =
                                    lower_entry.data(directory)
                                {
                                    println!(
                                        "[*] Found actual resource data with RVA {}",
                                        data_entry.offset_to_data.get(LE)
                                    );

                                    virtual_address = data_entry.offset_to_data.get(LE);
                                    size = data_entry.size.get(LE)
                                }
                            }
                        }
                    }
                }
                _ => {}
            })
    });

    if virtual_address > 0 && size > 0 {
        Some((virtual_address, size))
    } else {
        None
    }
}

fn u64_from_bytes(arr: &[u8]) -> Result<u64, Box<dyn Error>> {
    let fixed_arr: &[u8; 8] = arr.try_into()?;

    Ok(u64::from_be_bytes(*fixed_arr))
}

fn check_version(binary_data: &[u8], offset: usize) -> bool {
    binary_data[binary_data.len() - offset..].starts_with(MAGIC_TRAILER)
}

// fn write_to_file<P: AsRef<Path>>(path: P, content: &[u8]) -> std::io::Result<()> {
//     let mut file = File::create(path)?;
//     file.write_all(content)
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::fs::exists;
//     use tempfile::tempdir;
//
//     #[tokio::test]
//     async fn test_version_uno() {
//         let temp_dir = tempdir().unwrap();
//         let temp_path = temp_dir.path();
//
//         let binary_data = read("/Users/fli/Git/DenoDig/test/hello-v1.6.exe").expect("[!] Failed to open input file");
//
//         process_binary_file(
//             binary_data,
//         )
//             .await
//             .unwrap();
//
//         // Version uno only produces a bundle.js file.
//         let bundle_path = temp_path.join("bundle.js");
//
//         assert!(exists(bundle_path).unwrap());
//     }
//
//     #[tokio::test]
//     async fn test_version_dos() {
//         let temp_dir = tempdir().unwrap();
//         let temp_path = temp_dir.path();
//
//         process_binary_file(
//             Path::new("/Users/fli/Git/DenoDig/test/hello-v1.7.exe"),
//             temp_path,
//         )
//             .await
//             .unwrap();
//
//         // Version dos produces a bundle and a metadata file.
//         let bundle_path = temp_path.join("bundle.js");
//         let metadata_path = temp_path.join("metadata.json");
//
//         assert!(exists(bundle_path).unwrap());
//         assert!(exists(metadata_path).unwrap());
//     }
//
//     #[tokio::test]
//     async fn test_version_tres() {
//         let temp_dir = tempdir().unwrap();
//         let temp_path = temp_dir.path();
//
//         process_binary_file(
//             Path::new("/Users/fli/Git/DenoDig/test/telecraft_deno_1.44"),
//             temp_path,
//         )
//             .await
//             .unwrap();
//
//         // Version tres produces a node_modules folder, a source directory and a metadata file.
//         let metadata_path = temp_path.join("metadata.json");
//         let modules_path = temp_path.join("node_modules");
//
//         assert!(exists(metadata_path).unwrap());
//         assert!(exists(modules_path).unwrap());
//     }
//
//     #[tokio::test]
//     async fn test_version_quatro() {
//         let temp_dir = tempdir().unwrap();
//         let temp_path = temp_dir.path();
//
//         process_binary_file(
//             Path::new("/Users/fli/Git/DenoDig/test/telecraft_deno_1.46"),
//             temp_path,
//         )
//             .await
//             .unwrap();
//
//         // Version quatro produces a node_modules folder, a source directory and a metadata file.
//         let metadata_path = temp_path.join("metadata.json");
//         let modules_path = temp_path.join("node_modules");
//
//         assert!(exists(metadata_path).unwrap());
//         assert!(exists(modules_path).unwrap());
//     }
// }
