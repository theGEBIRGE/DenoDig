use clap::Parser;
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
use std::fs::{create_dir_all, read, File};
use std::io::Write;
use std::path::PathBuf;
use std::path::{absolute, Path};
use std::time::Instant;
use std::{env, process};

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

#[derive(Parser, Debug)]
#[command(
    name = "Deno Dig",
    version = "1.0.0",
    author = "Frederic Linn",
    about = "A tool for excavating application code and npm packages from stand-alone Deno binaries "
)]
struct Cli {
    /// Input file path (required)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory (optional, defaults to the current working directory)
    #[arg(short, long)]
    output_directory: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    print_logo();

    // Get the output path: use the provided one, or fallback to the current working directory.
    let mut output_directory = args.output_directory.unwrap_or_else(|| {
        env::current_dir().expect("[!] Failed to get the current executable path")
    });

    output_directory = output_directory.join("excavated");
    output_directory = absolute(output_directory)?;
    create_dir_all(&output_directory).expect("[!] Failed to create output directory");

    let input = Path::new("/Users/fli/Git/DenoDig/test/telegraf-2.0.exe");
    // let input = Path::new("/Users/fli/Git/DenoDig/test/telecraft_deno_1.46");
    // let input = Path::new("/Users/fli/Git/DenoDig/test/telecraft-linux-x86_64");
    // let input = Path::new("/Users/fli/Git/DenoDig/test/cli");

    process_binary_file(input, &output_directory).await?;

    Ok(())
}

async fn process_binary_file(
    input_path: &Path,
    output_directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let timer = Instant::now();

    let binary_data = read(input_path).expect("Failed to open file");

    if check_version(&binary_data, VERSION_UNO_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.6.0  <1.7.0");
        let bundle_pos_arr: &[u8; 8] = &binary_data[(binary_data.len() - 8)..].try_into()?;
        let bundle_pos = u64::from_be_bytes(*bundle_pos_arr);

        let bundle = &binary_data[bundle_pos as usize..&binary_data.len() - VERSION_UNO_OFFSET];

        write_to_file(&output_directory.join("bundle.js"), bundle).unwrap();
    } else if check_version(&binary_data, VERSION_DOS_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.7.0  <1.33.3");
        let pointers: &[u8; 16] = &binary_data[(binary_data.len() - 16)..].try_into()?;
        let (bundle_pos_arr, metadata_pos_arr) = pointers.split_at(8);

        let bundle_pos_arr: &[u8; 8] = bundle_pos_arr.try_into()?;
        let metadata_pos_arr: &[u8; 8] = metadata_pos_arr.try_into()?;

        let bundle_pos = u64::from_be_bytes(*bundle_pos_arr);
        let metadata_pos = u64::from_be_bytes(*metadata_pos_arr);

        let bundle = &binary_data[bundle_pos as usize..metadata_pos as usize];
        let metadata = &binary_data[metadata_pos as usize..binary_data.len() - VERSION_DOS_OFFSET];

        write_to_file(&output_directory.join("bundle.js"), bundle).unwrap();
        write_to_file(&output_directory.join("metadata.json"), metadata).unwrap();
    } else if check_version(&binary_data, VERSION_TRES_OFFSET) {
        println!("[*] Binary compiled with Deno >=1.33.3  <1.46");
        let trailer_data = &binary_data[binary_data.len() - TRAILER_SIZE..];

        let trailer = Trailer::parse(trailer_data)?.unwrap();
        let eszip_bytes = &binary_data[trailer.eszip_pos as usize..];

        let bufreader = BufReader::new(eszip_bytes);
        let (eszip, loader) = EszipV2::parse(bufreader).await?;

        let bufreader = loader.await?;

        let mut metadata = String::new();

        bufreader
            .take(trailer.metadata_len())
            .read_to_string(&mut metadata)
            .await
            .unwrap();

        write_to_file(&output_directory.join("metadata.json"), metadata.as_bytes()).unwrap();

        extract_modules(eszip, output_directory).await.unwrap();
        extract_packages(&trailer, &binary_data, output_directory)?;
    } else {
        println!("[*] Binary compiled with Deno >= 1.46");

        let file = object::File::parse(&*binary_data)?;
        let data;

        match file.format() {
            BinaryFormat::Elf => {
                println!("[+] ELF file detected");

                let offset_arr: &[u8; 4] = &binary_data[(binary_data.len() - 4)..].try_into()?;
                let negative_offset = u32::from_le_bytes(*offset_arr);

                let offset = binary_data.len() - negative_offset as usize;

                data = Vec::from(&binary_data[offset..binary_data.len() - 12]);
            }
            BinaryFormat::MachO => {
                println!("[+] Mach-O file detected");
                let section = file.section_by_name("d3n0l4nd").unwrap();

                println!("[+] Found section '{}'", section.name()?);

                data = Vec::from(section.data()?);
            }
            BinaryFormat::Pe => {
                println!("[+] PE file detected");

                let dos_header = pe::ImageDosHeader::parse(&*binary_data)?;
                let mut offset = dos_header.nt_headers_offset().into();
                let (nt_headers, data_directories) =
                    pe::ImageNtHeaders64::parse(&*binary_data, &mut offset)?;

                let header = nt_headers.file_header();
                let sections = header.sections(&*binary_data, offset).unwrap();

                let mut section_rva = 0;
                let mut section_raw_offset = 0;

                let mut found_section = false;

                for section in sections.iter() {
                    if let Ok(section_name) = std::str::from_utf8(&section.name) {
                        if section_name.starts_with(".pedata") {
                            println!(
                                "Found {:?} with virtual address {}, pointer to raw data {}",
                                section_name,
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
                    eprintln!("Error: .pedata section not found");
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
                panic!("[!] Unsupported binary format");
            }
        }

        let trailer = Trailer::parse(&data[0..TRAILER_SIZE])?.unwrap();

        let without_trailer = &data[TRAILER_SIZE..];

        let bufreader = BufReader::new(without_trailer);
        let (eszip, loader) = EszipV2::parse(bufreader).await?;
        let bufreader = loader.await?;

        let mut metadata = String::new();

        bufreader
            .take(trailer.metadata_len())
            .read_to_string(&mut metadata)
            .await
            .unwrap();

        write_to_file(&output_directory.join("metadata.json"), metadata.as_bytes()).unwrap();

        extract_modules(eszip, output_directory).await.unwrap();
        extract_packages(&trailer, &without_trailer, output_directory)?;
    }

    println!("===========================================");
    println!("✓ Digging took : {:.2}s", timer.elapsed().as_secs_f64());

    Ok(())
}

async fn extract_modules(eszip: EszipV2, output_directory: &Path) -> std::io::Result<()> {
    for specifier in eszip.specifiers().iter() {
        if let Some(module) = eszip.get_module(specifier) {
            println!("[+] Handling module '{}'", specifier);

            let source = module.source().await.unwrap();
            let file_path = output_directory.join(specifier);
            let absolute_path = absolute(file_path)?;

            if !absolute_path.starts_with(output_directory) {
                panic!("[!] Path traversal detected")
            }

            if let Some(parent) = absolute_path.parent() {
                create_dir_all(parent)?;
            }

            write_to_file(absolute_path, &source)?;
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
    output_directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let vfs_data = &without_trailer[trailer.npm_vfs_pos as usize..trailer.npm_files_pos as usize];

    // If no packages are included, the JSON will be `null`.
    let vfs_root: Option<VirtualDirectory> = serde_json::from_slice(vfs_data)?;

    if let Some(virtual_directory) = vfs_root {
        let npm_files = &without_trailer[trailer.npm_files_pos as usize..];

        traverse_directories(virtual_directory, npm_files, output_directory, "")?;
    };

    Ok(())
}

pub fn traverse_directories(
    dir: VirtualDirectory,
    npm_files: &[u8],
    output_directory: &Path,
    parent_path: &str,
) -> Result<(), Box<dyn Error>> {
    let current_path = if parent_path.is_empty() {
        dir.name
    } else {
        format!("{}/{}", parent_path, dir.name)
    };

    for entry in dir.entries {
        match entry {
            VfsEntry::File(file) => {
                let offset = file.offset;

                let file_bytes = &npm_files[offset as usize..(offset + file.len) as usize];

                let file_path = output_directory.join(&current_path).join(file.name);

                let absolute_path = absolute(&file_path).unwrap();

                if !absolute_path.starts_with(output_directory) {
                    panic!("[!] Path traversal detected")
                }

                if let Some(parent) = absolute_path.parent() {
                    create_dir_all(parent).expect("[!] Failed to create directories");
                }

                write_to_file(absolute_path, file_bytes)?;
            }
            VfsEntry::Dir(sub_dir) => {
                traverse_directories(sub_dir, npm_files, output_directory, &current_path)?;
            }
            VfsEntry::Symlink(_symlink) => {
                panic!("[!] Can't handle symlinks yet")
            }
        }
    }

    Ok(())
}

fn u64_from_bytes(arr: &[u8]) -> Result<u64, Box<dyn Error>> {
    let fixed_arr: &[u8; 8] = arr.try_into()?;

    Ok(u64::from_be_bytes(*fixed_arr))
}

fn check_version(binary_data: &[u8], offset: usize) -> bool {
    binary_data[binary_data.len() - offset..].starts_with(MAGIC_TRAILER)
}

fn write_to_file<P: AsRef<Path>>(path: P, content: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content)
}

fn print_logo() {
    let logo = r#"
                    ██████████████████████████████████░█ ███████████
            ██████████             ██████████████████ █████ ███░████
          ██████                       █████████████▒████▒███████▒████
        ██ ░                     █       █████████░█████████████████▒███
       █                      ██  ██      ██████████████████████████ ████
                              ███████      ███████▒██████████████████████▒
     ░                         █████        ███████████████████████████████
    █                             ░          ████▒██████████████████████████
    ░                                        ░██████████████████████████████
                                              ▒█████████████████████████████
    █                                          █████████████████████████████
    █████████████████   ░░░░       ██████      ███████████ ░  ██████████████
    ████████████████████████████████           █████████░        ███████████
    █████▒█████████████████████ ░          ▒█▒ ████████░         ███████████
    ████  ███████████████               ▒███   ▒██████░███  ███ ▒████▒███▒██
    ███   █████████                   ████     ▒██████ ██░█ ████ ███████████
    ███░                         ░█▒ ███▒█ ▒    ██████ █░██▒     ███████▒███
      ███                  ▒       ██▒           ███████     ███     ███████
    ░ ██████             ░ ▒█ ░░ ██▒  █ ▒        ██████████████     ▒ ██████
      ██████████████████ ░  ░ ██▒█ █             ████████▒████▒   █ ████▒█▒
    █████████████████████████████ ▒               ██░ █ ▒ ███ ▒██ ▒       ██
    ████████████████████████████▒            ░█   ░█  ████  █ ░░░ ░█░ ▒█████
     ██ ▒██████████████████  ░ ▒            █      ▒█████████░▒█▒▒██ ██████
      █░  ░█████████████████              ▒         ██████████ █████ ▒▒░ ░
       ███▒▒████████████████ █   ░                  ███▒███████ █████████
        █████▒ ██████████▒▒░  ░               ░█▒▒█▒ ▒ ░     █████████▒
          █████▒▒███████                  ▒  ░ ▒▒ █░░          ░██▒ ▒▒
             ███████▒█▒█▒██▒██       ░█▒  ▒▒ ▒  ▒█░    ▒     ▒  ▒▒ █
                ▒██  ▒█ █▒█ ████  █▒ █ ▒█▒████▒ ▒▒▒█▒    ▒  ██▒
                  DENO DIG DENO DIG DENO DIG DENO DIG DENO DIG
    "#;
    println!("{}", logo);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::exists;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_version_uno() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        process_binary_file(
            Path::new("/Users/fli/Git/DenoDig/test/hello-v1.6.exe"),
            temp_path,
        )
        .await
        .unwrap();

        // Version uno only produces a bundle.js file.
        let bundle_path = temp_path.join("bundle.js");

        assert!(exists(bundle_path).unwrap());
    }

    #[tokio::test]
    async fn test_version_dos() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        process_binary_file(
            Path::new("/Users/fli/Git/DenoDig/test/hello-v1.7.exe"),
            temp_path,
        )
        .await
        .unwrap();

        // Version dos produces a bundle and a metadata file.
        let bundle_path = temp_path.join("bundle.js");
        let metadata_path = temp_path.join("metadata.json");

        assert!(exists(bundle_path).unwrap());
        assert!(exists(metadata_path).unwrap());
    }

    #[tokio::test]
    async fn test_version_tres() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        process_binary_file(
            Path::new("/Users/fli/Git/DenoDig/test/telecraft_deno_1.44"),
            temp_path,
        )
        .await
        .unwrap();

        // Version tres produces a node_modules folder, a source directory and a metadata file.
        let metadata_path = temp_path.join("metadata.json");
        let modules_path = temp_path.join("node_modules");

        assert!(exists(metadata_path).unwrap());
        assert!(exists(modules_path).unwrap());
    }

    #[tokio::test]
    async fn test_version_quatro() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        process_binary_file(
            Path::new("/Users/fli/Git/DenoDig/test/telecraft_deno_1.46"),
            temp_path,
        )
        .await
        .unwrap();

        // Version quatro produces a node_modules folder, a source directory and a metadata file.
        let metadata_path = temp_path.join("metadata.json");
        let modules_path = temp_path.join("node_modules");

        assert!(exists(metadata_path).unwrap());
        assert!(exists(modules_path).unwrap());
    }
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

    rcdata_tables.iter().for_each(|x| {
        x.entries.iter().for_each(|entry| match entry.name_or_id() {
            ResourceNameOrId::Name(name) => {
                let name_or_id = entry.name_or_id.get(LE);
                if let Ok(name) = name.to_string_lossy(directory) {
                    if name.eq("D3N0L4ND") {
                        println!(
                            "Found Deno resource \"{}\" at offset (0x{:X})",
                            name, name_or_id
                        );
                        let test = entry.data(directory).unwrap();
                        let test_table = test.table().unwrap();

                        for lower_entry in test_table.entries {
                            match lower_entry.data(directory) {
                                Ok(ResourceDirectoryEntryData::Data(data_entry)) => {
                                    println!("WE FOUND RESOURCE DATA");
                                    println!(
                                        "VirtualAddress {}",
                                        data_entry.offset_to_data.get(LE)
                                    );
                                    println!("Size {}", data_entry.size.get(LE));
                                    println!("CodePage {}", data_entry.code_page.get(LE));
                                    println!("Reserved {}", data_entry.reserved.get(LE));

                                    virtual_address = data_entry.offset_to_data.get(LE);
                                    size = data_entry.size.get(LE)
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        })
    });

    Some((virtual_address, size))
}
