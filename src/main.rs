use clap::Parser;
use eszip::EszipV2;
use futures::io::BufReader;
use futures::AsyncReadExt;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs::{create_dir_all, read, File};
use std::io::Write;
use std::path::PathBuf;
use std::path::{absolute, Path};
use std::time::Instant;

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
    version = "1.0",
    author = "Frederic Linn",
    about = "A tool for excavating application code and npm packages from Deno compiled binaries"
)]
struct Cli {
    /// Input file path (required)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory (optional, defaults to the current executable's path)
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

    process_binary_file(&args.input, &output_directory).await?;

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
        let section = file.section_by_name("d3n0l4nd").unwrap();

        println!("[+] Found section '{}'", section.name()?);

        let data = section.data()?;
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
                      %*+*++*+++*#%##%%%%%%%%%##*---=##%########+#+=====+*#***#%%%%%%%
              #%#*++*+++++++++#%#------*%%%=--:-=-##%#####*++*+-+=-=--=+####--=+#####%
           ####***+*:::-++++=+*%-++*==-=*%+==+=*#%@#*=-*+*#%%%-+%###-#####=====++*###*=--
        %%%%%%###*+%%%@+=+==+*#%-----*+-----=-=---=::--#=#**#++%#@@*==%@#++*+*++=--::%=--=+*
      %+-=----=%#+%*#*#++++***==++****#++*+**+-#*++*-=#--:+:*=+%**..=-==##*##**#-:::-%#*%#%##*
     +#*=#++%-=-#%-=*+=+#++::::-:+*===++*==**+=%%#%:#%##**-=#::-==-:.--==*..=++#+==*%#----:---+
    .:=%*@%%@=%@@====:...*=+=--=--+#=+:=-++++=%*%#++##%%%###-=*#*==-+#**+....::++*=-=+=+++*+*=*%
   ***=#%+@@+=+-@+==-:.-:-#==+=-=+====-=++=======-...:+*+++.+##+#+#=-*+*===+=*+--*%%@%-=@%%@=+@--
  ::::#=%**%@*=*=..***%%+=***##*@#+===*+=--==++*:#%#=-=-=%-:%%*##%@@*=++==*#==*%--=-==+%@@#+***@++
 **=*=====-=+--..:..:+++=++++=*-+-++*#*##+%@%**++%+=%*=%+##%+*@@*+*#++%+#==+@#=+*=*=*+%#+**#%+***%+
 =*+=-+%*=*=##+%+=#%=*+=++@@%%*#=%##*%##%%*%#@###++#%#%%@##@@@%%*%*+@@%=#=+%*-==+=+*=-=+*=-==---+=-
=+-+=*===*===#%**+#++%#***@#%#*%%@@%@%#=####%%#%@@@%%#%#%#@#@%@%%#**#####+#@%@#%%=++@==-=%---*=-:-+@
@%#%-+%=#*+#=%%@@+@@@**##%@#%#+#%#%%@@%#####%%%%@%###%#%%@#*%#%%@#%%*@#*#%%-%*@%+*==****+++@#=+-*@@=
#@+@#@#@%@@%#@@##%%#@%%%##%%%#%%%#%%%%*%%%@%@%@@%%%%%@@@%%%%%%#@%%%%%%%*#@##%*#*@#*%#@-++#@%%@@@@@#=
%@%@@##%@%%@@-**@*%%*%%#**%%*%#%###%%%%*%@@@@@%@@@%%%@*%%@@@@@@##*##%%#%#%**%*#*%%@%@%+%*%#%*#@#@+#%
%#*%##%@**%%@@@@%#@@@*@#%%%@@%%@%*@@@@@@@@@@#*.............=%@@@@@@@@@%%@%##*%%%#@#%:@%+%@@@#%@@@*@-
@@%@###%%#%=#@@%%%%###%%@@@@%@@@@@@@@@+:......................:@@@@@@@@@@%#%%%#%##%%#@@#%-+@##%#%=##
%#%%##**%#=%#@@%@%%@@@@@@@@@@@@@%%-................ ....@@......:@@@@@@@@@-%@%%@@%#%%@@*%@#+=@@%%##%
@@@@*#%##@#@@@@@@@@@@@@@@@@@@@%*......................@@::@@......%@@@@@@@@@@@@@@@@%@@@@%%##+#**%%@#
@#@@#+%@@@@@@@@@@@@@@@@@@@@@@@:.......................@@@@@@:.....:%@@@@@@+@@@@@%@%@@%#%@@@@%@#*@##%
@@@@@=@@@@%@@@@@@@@@@@@@@@@@%:...................:....:@@@@%:....:.:%@@@@@@@@@@@@@@@@%@@@@@@%%@@%%#+
@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.......:..........:........:=-:...:..:::@@@@-@@@@@@@%%@@@@%%%@@@%@@@@@%
@@@@@@@@@@@@@@@@@@@@@@@@@@@@:........:...:.::......::....:::......-::+%@@#@@@@@@@@@@@@@@%@%@@%%%@%@@
@@@@@@@@@@@@@@@%%%%%###@@@@@=::::::.....:.....:.........-:......::..:-#@@*@@@@@@@@@@@@@%@@%%+%%%#@%@
@@@@@@@@@@@@%%%##***+++*#@@@#+++==--=-:-:-::--:::.........::.:=-------#%#+##%@@@@@@@@@@@@@@@@%%@%#%@
=-------@@@%%%#*#*+*+++++%@@@%%%##%@@%@@@%%%@#@*-+====*=###%@@@@%+...-**##%##%@@@*+==+**#@@@@%@%%#%%
%=---------=###***+==-==+%%%%######*##@@@@@@@@@@@@@@@@@@@@@%-:....::=++***###%@@------=++*%@=@@@%%%%
---:-:-:--===#@%%#+*++++*##*#%#**+*#@@@@@@@@@@@@@@@@@@*-.....:.:-+++*++**+*#%@@::::::--=+##%%@@%#%%@
=------:-=====#%#%*#######*#*%*+-+@@@@@@@@@@@@@@%:.......=..-===****===***#%@%*@@@=+%@@:#@%%@%#***##
=--:-@--===+===++*#**#%#==**###-::#@@@@@@@#:........::::--==++***+==+==+%@%%%+=%%=*-@@@@+@@@%+*#@***
==-=-=#-====+++*%%#%+--=----%%#=::........:::.:-:==-=++=+=+*+**%+*==--=+@###%*+*-@@-=:::=**%#****%*#
+==-==-@-*+*#+**###==-----===+***==------=-=====++++++++++++++++=--====-*#####%+=---=*@@-:--=***%#*#
=+++==-=@=+++*+##**++==----=++*#%%##++++++++++++++++*+++++#+*+*===---=--=######*%###+%%-::::++*#####
%%#@@@%%*@***+*#.:::-+====-=++##%%@@#%%#******++++++++*++*++==--::-::::=+##%#####+#*%*==-#*=###***+#
-=@@@@@%*#%#**::-::=-=-%+*@##@@%#%%%@@@@@@@@@%###########+==-::.::..:-=+=-##:-#=++**%+=%=#+--:::-+%%
@%-*#**-=@%#:::::::@:==-#**%+%#%%%%@%@@@@@@@@%#%#######*+=-::-:..:::=+++--=%.=*@%%-#%=+##+*+=-%%@#*%
@@+*%%*++.+:--:-:::::-+-=%#######**##%%@@@@@@@##****+=-::-::::-::--=++=-::=#%####**%@---=#+%.#@%@%%#
#+#+#%@@%++----==:@*+-+==*%#*+*++==+###%%@@@@@%%##*+++=--=:=+=-==+++=:-::--=#***#+**%%-@@%@@#-+-=**#
##+@+%+*%+=++##%##%@++*#+%@*%=**##++****##@@@@%####*+++===++==-===-:::::::-=%+*+++#*#@%=@@@@@@@@@#=#
+#@*@%+#@@%%%%%%#######%**%::.:+#+#+*++**#%@%@%#*++===-=+::::-==-:..:.=#++****::::--%@*@%%#**#-=+#=+
**--:..:::%@@%@*@.::-**#*+-=@+::.:%##*+++#%####**+=+-==:-::::-:::::::===*##=---::---++=#+#=+*=:=*++*
##%*=+-::-+=++++-=-:--:#*+*@%@:::*-%**#*#*+%*@+*****##=--:::#*%+#+**=++*##--:-----=%++++#++*=++##===
*++#%@*==%+@+++#+=---:---#+-:::-=-:-.-.+#*@+-*#*+#%#-+#**++=+#*+#%@++*+#****-=--=++=##*:-.#..=::--*-
+*=**=*@*+#+-==#*+=+*##@@+*::.+@@%@#%=:..-*=*=*+*@*-=+=**=*%*@%#%%*+##*%#**%+**+#*+-#.+..::-==#**:#*
 -%***+===#*%%+*=%+@@%*+++-::::.::+=#++@@#=:...%.:*+#@@*+@*++***+=+*#=++#=*@%%##+.=.:.:%+%++@.*#*-#
 +-++++#%#*%%%%*%%%-##+*-++==--=++#++-..-=++@%-:%.-**+=*+=+++#+=--+=++*++#++-.=.+.:#*%.#%.%%.##:%@*
  +=:+*@*-:::::::--%%%=-=*++=*%%#%+:.......=+#=#*%::-:***#%*-+--===--*+*+##.:::-=%@@:.%::%:*%:##*#
   *+----=----=-::::--@%*--*+**=+*:.....::--+*%+=+++*--=*=*+==+*+++*%#%=#..::=#%.@@.%%.%%.%######
    %#+=***++***=:**+=-:-%%==+=++-@@@--+-:+++*%++*+=---==++#=+*@%#**%++:.**#@-.@@.%@-%%=#@*%%@:.
     %++#%%%%%%*++**%##**+-:+::*..%%..:@@@=+*++#+--=-==+=+%%==+++*#--.=*%+%:.%@.@@*#:.......%--
      *=*%%%%%%*+*#%%###%%%%*+-:+=%:@@-...-++*%------***##=#%****..-*%.%.@.%%:%@%#-.......:::-
        #**#*#@##*#@%***#++++*#%*=--::-===#+#------==+***##****#:.%-@:=+=###:-##%=:--:::....
           @@@@@%#+@%#%%%%%%**++*=+#+==+++=***+*+-=-==++*#*#*..#%@:@*#+***+-+@%*+-==+*.-@
              %@@%#*#**+++*#####%**=*+*#*=+*##++##+*#%%#***.-%+**#*+=-=--=+#*****++*+-
                  ++=+==+*+*+*++::.:::::+#**#*+**%@%%+**+:-#%##%%++=+++=**##%+*+*%
                   DENO DIG DENO DIG DENO DIG DENO DIG DENO DIG DENO DIG DENO DIG
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
