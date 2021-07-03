package chiseltest.fuzzing

import org.scalatest.flatspec.AnyFlatSpec

import java.io.ByteArrayInputStream

class RfuzzTargetTests extends AnyFlatSpec {
  behavior of "RfuzzTarget"

  it should "execute a single input" in {
    val fuzzer = Rfuzz.firrtlToTarget("src/test/resources/fuzzing/gcd.fir", "test_run_dir/rfuzz")
    val input = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).map(_.toByte)
    val coverage = fuzzer.run(new ByteArrayInputStream(input))
    println(coverage)
    fuzzer.finish()
  }

}
