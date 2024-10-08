use std::error::Error;
use object::{Object, ObjectSection};
use std::fs::{File, read, create_dir_all};
use std::io::Write;
use std::path::{Path, absolute};
use eszip::EszipV2;
use futures::AsyncReadExt;
use futures::io::BufReader;

const TRAILER_SIZE: usize = size_of::<Trailer>() + 8; // 8 bytes for the magic trailer string.
const MAGIC_TRAILER: &[u8; 8] = b"d3n0l4nd";

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
}

fn u64_from_bytes(arr: &[u8]) -> Result<u64, Box<dyn Error>> {
    let fixed_arr: &[u8; 8] = arr.try_into()?;

    Ok(u64::from_be_bytes(*fixed_arr))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let binary_data = read("")?;
    let file = object::File::parse(&*binary_data)?;
    let section = file.section_by_name("d3n0l4nd").unwrap();

    println!("Found section '{}'", section.name()?);

    let data = section.data()?;
    let trailer = Trailer::parse(&data[0..TRAILER_SIZE])?.unwrap();

    println!("eszip_pos: {}", trailer.metadata_pos);
    println!("metadata_pos: {}", trailer.metadata_pos);
    println!("npm_vfs_pos: {}", trailer.npm_vfs_pos);
    println!("npm_files_pos: {}", trailer.npm_files_pos);

    let bufreader = BufReader::new(&data[TRAILER_SIZE..]);

    // "Once this function returns, the data section will not necessarially have been parsed yet.
    // To parse the data section, poll/await the future returned in the second tuple slot."
    // https://docs.rs/eszip/0.79.1/eszip/v2/struct.EszipV2.html#method.parse
    let (eszip, loader) = EszipV2::parse(bufreader).await?;

    let bufreader = loader.await?;

    let mut metadata = String::new();

    bufreader
        .take(trailer.metadata_len())
        .read_to_string(&mut metadata)
        .await
        .unwrap();

    let base_directory = Path::new("");

    handle_modules(eszip, base_directory).await;

    println!("metadata: {}", metadata);

    Ok(())
}

async fn handle_modules(eszip: EszipV2, base_directory: &Path) {
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

        let mut file = File::create(Path::new(&absolute_path))
            .expect("Failed to create file");
        file.write_all(&source).expect("Failed to write to file");
    }
}