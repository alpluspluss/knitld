# knitld

knitld or knit in short is a MachO linker designed to be small and is able to use cross-platform.
knit is made as an educational project on Apple's MachO binary file format just before my highschool
spring semester ends.

The knit codebase tries to be as concise as possible to not leave redundant 
code to reduce readability and maintainability. It is also noteworth to mention that this project
serves as a prototype for a newer version that implements concurrent linking.

## Status

knit successfully implements valid but minimal Mach-O file linking without code signing. This project
ended at April 18th Friday 5:00 PM and left as is, uncompleted. It lacks GOT handling during static linking and
dynamic linking and its data structure, export trie.

## License

This project is licensed under the [MIT License](LICENSE.txt).
