use eszip::EszipV2;
use futures::io::BufReader;
use futures::AsyncReadExt;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{create_dir_all, read, File};
use std::io::Write;
use std::path::{absolute, Path};
use std::time::Instant;

const MAGIC_TRAILER: &[u8; 8] = b"d3n0l4nd";
const TRAILER_SIZE: usize = size_of::<Trailer>() + MAGIC_TRAILER.len();

#[derive(Debug)]
struct Trailer {
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
        let eszip_archive_pos = u64_from_bytes(eszip_archive_pos)?;
        let metadata_pos = u64_from_bytes(metadata_pos)?;
        let npm_vfs_pos = u64_from_bytes(npm_vfs_pos)?;
        let npm_files_pos = u64_from_bytes(npm_files_pos)?;

        Ok(Some(Trailer {
            eszip_pos: eszip_archive_pos,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let timer = Instant::now();

    let binary_data = read("/Users/fli/Git/DenoDig/test/telecraft_deno_1.46")?;
    let file = object::File::parse(&*binary_data)?;

    // TODO: If section_by_name returns nothing, we know that we deal with an old binary.
    let section = file.section_by_name("d3n0l4nd").unwrap();

    println!("Found section '{}'", section.name()?);

    let data = section.data()?;
    let trailer = Trailer::parse(&data[0..TRAILER_SIZE])?.unwrap();

    // From now on we need to get rid of the leading trailer in order to calculate the correct offsets.
    let without_trailer = &data[TRAILER_SIZE..];

    if cfg!(debug_assertions) {
        println!("Deno trailer structure: {:?}", trailer);
    }

    let bufreader = BufReader::new(without_trailer);

    // "Once this function returns, the data section will not necessarially have been parsed yet.
    // To parse the data section, poll/await the future returned in the second tuple slot."
    // https://docs.rs/eszip/0.79.1/eszip/v2/struct.EszipV2.html#method.parse
    let (eszip, loader) = EszipV2::parse(bufreader).await?;
    let bufreader = loader.await?;

    let mut metadata = String::new();

    println!("metadata: {}", metadata);

    bufreader
        .take(trailer.metadata_len())
        .read_to_string(&mut metadata)
        .await
        .unwrap();

    let base_directory = Path::new("/Users/fli/Git/DenoDig/test/extracted");

    extract_modules(eszip, base_directory).await;

    // Trying extract the packages is safe, because the virtual file system is `null` in case no packages are used.
    extract_packages(&trailer, &without_trailer)?;

    println!("🦖 digging took : {}s", timer.elapsed().as_secs_f64());
    Ok(())
}

async fn extract_modules(eszip: EszipV2, base_directory: &Path) {
    for specifier in eszip.specifiers().iter() {
        println!("Handling module '{}'", specifier);

        let module = match eszip.get_module(specifier) {
            Some(module) => module,
            None => {
                eprintln!("Failed to get module for {}", specifier);
                continue;
            }
        };

        let source = module.source().await.unwrap();

        let file_path = base_directory.join(specifier);
        let absolute_path = absolute(file_path).unwrap();

        if !absolute_path.starts_with(base_directory) {
            panic!("Path traversal detected")
        }

        if let Some(parent) = absolute_path.parent() {
            create_dir_all(parent).expect("Failed to create directories");
        }

        let mut file = File::create(Path::new(&absolute_path)).expect("Failed to create file");
        file.write_all(&source).expect("Failed to write to file");
    }
}

pub fn extract_packages(trailer: &Trailer, without_trailer: &[u8]) -> Result<(), Box<dyn Error>> {
    let vfs_data = &without_trailer[trailer.npm_vfs_pos as usize..trailer.npm_files_pos as usize];

    // TODO: Put this behind a verbose or debug flag.
    if cfg!(debug_assertions) {
        // println!("Serialized virtual file system : {}", std::str::from_utf8(vfs_data)?);
    }

    // If no packages are included, this will be `null`.
    let vfs_root: Option<VirtualDirectory> = serde_json::from_slice(vfs_data)?;

    if let Some(virtual_directory) = vfs_root{
        let npm_files = &without_trailer[trailer.npm_files_pos as usize..];

        traverse_directories(virtual_directory, npm_files, "")?;
    };

    Ok(())
}

pub fn traverse_directories(
    dir: VirtualDirectory,
    npm_files: &[u8],
    parent_path: &str,
) -> Result<(), Box<dyn Error>> {
    let base_directory = Path::new("/Users/fli/Git/DenoDig/test/extracted");

    let current_path = if parent_path.is_empty() {
        dir.name.clone()
    } else {
        format!("{}/{}", parent_path, dir.name)
    };

    for entry in dir.entries {
        match entry {
            VfsEntry::File(file) => {
                let offset = file.offset;

                let file_bytes = &npm_files[offset as usize..(offset + file.len) as usize];

                let file_path = base_directory.join(&current_path).join(file.name);

                let absolute_path = absolute(&file_path).unwrap();

                if !absolute_path.starts_with(base_directory) {
                    panic!("Path traversal detected")
                }

                if let Some(parent) = absolute_path.parent() {
                    create_dir_all(parent).expect("Failed to create directories");
                }

                let mut file =
                    File::create(Path::new(&absolute_path)).expect("Failed to create file");

                // TODO: PUt this behind a debug or verbose flag.
                // println!("Extracting to {:?}", file_path);
                file.write_all(&file_bytes)
                    .expect("Failed to write to file");
            }

            VfsEntry::Dir(sub_dir) => {
                traverse_directories(sub_dir, npm_files, &current_path)?;
            }

            VfsEntry::Symlink(_symlink) => {
                panic!("Can't handle symlinks yet")
            }
        }
    }
    Ok(())
}

fn u64_from_bytes(arr: &[u8]) -> Result<u64, Box<dyn Error>> {
    let fixed_arr: &[u8; 8] = arr.try_into()?;

    Ok(u64::from_be_bytes(*fixed_arr))
}
