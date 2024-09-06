Flowcharts and other diagrams of the system.

To build, you will need a recent version of PlantUML.

Download the JAR file from
[here](https://github.com/plantuml/plantuml/releases/latest) (use the one
named something like `plantuml-1.yyyy.mm.jar`).  Place it somewhere to keep.

Then, set up a shell script wrapper to execute this jar file named
`plantuml`.  The contents can be as simple as:

```sh
#!/bin/sh
exec java -jar /path/to/plantuml-xxx.jar "$@"
```

Alternatively, set up a `binfmt` wrapper to allow running JAR files
directly.  On Debian and Ubuntu, you can simply
`sudo apt install jarwrapper`.  Then set it executable with
`chmod a+x plantuml-xxx.jar`, and create a symlink to it named
`plantuml` somewhere in your `PATH`, e.g.:
`ln -s /path/to/plantuml-xxx.jar $HOME/.local/bin/plantuml`.

Then you can simply run `make` here.  Output will be placed in
`output/`.
