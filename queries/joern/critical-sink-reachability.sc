import java.nio.file.{Files, Paths}

def clean(value: String): String = value.replace('\t', ' ').replace('\n', ' ')

@main def exec(cpgFile: String, out: String) = {
  importCpg(cpgFile)
  val sourcePattern = "(?i).*(request|handler|route|parse|decode|deserialize|read|recv|input|dispatch).*"
  val sinkPattern = "(?i).*(exec|spawn|system|popen|eval|dlopen|loadlibrary|memcpy|memmove|mmap|require|import).*"
  val sources = cpg.method.name(sourcePattern).parameter
  val rows = cpg.call.name(sinkPattern)
    .filterNot(call => call.name.matches("(?i).*systemexit.*"))
    .filterNot(call => call.code.matches("(?i)^\\s*(import|from)\\b.*"))
    .filter(call => call.argument.reachableBy(sources).nonEmpty)
    .l
  val header = "kind\tfile\tline\tmethod\tcode"
  val body = rows.map { call =>
    Seq(
      "sink-reachability",
      call.file.name.headOption.getOrElse(""),
      call.lineNumber.getOrElse(-1).toString,
      call.method.name,
      call.code
    ).map(value => clean(value.toString)).mkString("\t")
  }
  Files.writeString(Paths.get(out), (header +: body).mkString("\n") + "\n")
}
