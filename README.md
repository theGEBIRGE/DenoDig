# Deno Dig
<img src="resources/logo.png" alt="A white sock puppet underground between dinosaurs and skeletons">

Deno Dig
([/ˈdiːnoʊ ˈdɪɡ/](http://ipa-reader.xyz/?text=ˈdi%CB%90no%CA%8A)) aka  🦖🍆 is a tool that excavates application code
and npm packages from stand-alone [Deno](https://deno.com) binaries.

It can handle all the different iterations of `deno compile`:

1) `>=1.6.0 <1.7.0`: Bundle appended to the Deno binary
2) `>=1.7.0 <1.33.3`: Metadata + bundle appended to the Deno binary
3) `>=1.33.3 <1.46`: [eszip](https://github.com/denoland/eszip) appended to the Deno binary (introduction of npm package support)
4) `>= 1.46`: [eszip](https://github.com/denoland/eszip) included in an object file section of the Deno binary 

I've written an [article](https://gebir.ge/blog/denos-getting-digged-down-12/) where I go into more details about the whole process.

## Usage
```shell
Usage: DenoDig [OPTIONS] --input <INPUT>

Options:
-i, --input <INPUT>
Input file path (required)
-o, --output-directory <OUTPUT_DIRECTORY>
Output directory (optional, defaults to the current working directory)
-h, --help
Print help
-V, --version
Print version
```

## Demo
https://github.com/user-attachments/assets/bce1191b-b249-4b3a-93f8-77d1666af04e

## WebAssembly version
The `web` directory contains a sexy webpage for the Wasm build of the `deno-dig-lib`.

The Wasm blob and JavaScript glue is not included in the repository.
In order to build them, you need [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) installed.

Now you can do something like this:
```shell
cd deno-dig-lib
wasm-pack build --target web --release --no-typescript --no-pack --out-dir "../web/pkg"
cd ../web
python3 -m http.server
```

## Acknowledgements
+ [Deno Land](https://deno.com) for creating an awesome project and letting me borrow some structs
+ Original Deno logo by [Ryan Dahl](https://tinyclouds.org) (according to [this](https://deno.com/artwork))
+ The [Googlers](https://blog.google/products/chrome/chrome-dino/) for creating the dinosaur sprite used in the web version