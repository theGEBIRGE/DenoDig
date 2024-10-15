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


https://github.com/user-attachments/assets/948084f4-75f6-408d-b86d-0f54fc432cdf


## Acknowledgements
+ [Deno Land](https://deno.com) for creating an awesome project and letting me borough some structs
+ Original Deno logo by [Ryan Dahl](https://tinyclouds.org) (according to [this](https://deno.com/artwork))
