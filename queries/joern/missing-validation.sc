import java.nio.file.{Files, Paths}

def clean(value: String): String = value.replace('\t', ' ').replace('\n', ' ')

@main def exec(cpgFile: String, out: String) = {
  importCpg(cpgFile)
  val sinkPattern = "(?i).*(exec|spawn|system|popen|eval|dlopen|loadlibrary|memcpy|memmove|mmap|require|import).*"
  val guardPattern = "(?i).*(validate|verify|authorize|authenticate|sanitize|checkbounds|checklength).*"
  val rows = cpg.call.name(sinkPattern)
    .filterNot(call => call.name.matches("(?i).*systemexit.*"))
    .filterNot(call => call.code.matches("(?i)^\\s*(import|from)\\b.*"))
    .filter(sink => sink.controlledBy.isCall.name(guardPattern).isEmpty)
    .l
  val header = "kind\tfile\tline\tmethod\tcode"
  val body = rows.map { call =>
    Seq(
      "missing-validation",
      call.file.name.headOption.getOrElse(""),
      call.lineNumber.getOrElse(-1).toString,
      call.method.name,
      call.code
    ).map(value => clean(value.toString)).mkString("\t")
  }
  Files.writeString(Paths.get(out), (header +: body).mkString("\n") + "\n")
}
