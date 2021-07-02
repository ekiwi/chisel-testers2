package chiseltest.fuzzing

import chiseltest.internal.WriteVcdAnnotation
import chiseltest.simulator.{TopmoduleInfo, TreadleSimulator, VerilatorSimulator, VerilatorUseJNI}
import firrtl.{FileUtils, LowFirrtlEmitter}
import firrtl.options.{Dependency, TargetDirAnnotation}
import firrtl.stage.{FirrtlCircuitAnnotation, FirrtlSourceAnnotation, FirrtlStage, RunFirrtlTransformAnnotation}
import org.scalatest.flatspec.AnyFlatSpec

import java.io.ByteArrayInputStream

class RfuzzTargetTests extends AnyFlatSpec {
  behavior of "RfuzzTarget"

  private def loadFirrtl(name: String): firrtl.CircuitState = {
    val src = FileUtils.getTextResource(name)

    // we need to compile the firrtl file to low firrtl + add mux toggle coverage and meta reset
    val annos = Seq(
      RunFirrtlTransformAnnotation(Dependency(pass.MuxToggleCoverage)),
      RunFirrtlTransformAnnotation(Dependency(pass.MetaResetPass)),
      FirrtlSourceAnnotation(src),
      RunFirrtlTransformAnnotation(Dependency[LowFirrtlEmitter]),
      TargetDirAnnotation("test_run_dir"), // not optimal but better than polluting the root dir
      // for now we would like to have a VCD
      WriteVcdAnnotation,
      // if we use verilator, we want to use JNI
      VerilatorUseJNI,
    )
    val stage = new FirrtlStage
    val r = stage.execute(Array(), annos)

    val circuit = r.collectFirst { case FirrtlCircuitAnnotation(c) => c }.get
    firrtl.CircuitState(circuit, r)
  }

  it should "execute a single input" in {
    val state = loadFirrtl("/fuzzing/gcd.fir")
    val info = TopmoduleInfo(state.circuit)
    //val dut = TreadleSimulator.createContext(state)
    val dut = VerilatorSimulator.createContext(state)
    val fuzzer = new RfuzzTarget(dut, info)
    val input = Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).map(_.toByte)
    val coverage = fuzzer.run(new ByteArrayInputStream(input))
    println(coverage)
    dut.finish()
  }

}
