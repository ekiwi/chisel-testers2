// Copyright 2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Kevin Laeufer <laeufer@cs.berkeley.edu>

package chiseltest.fuzzing

import chiseltest.simulator._
import firrtl._
import firrtl.options.{Dependency, TargetDirAnnotation}
import firrtl.stage._
import logger.{LogLevel, LogLevelAnnotation}

object Rfuzz {

  val DefaultAnnotations = Seq(
    RunFirrtlTransformAnnotation(Dependency(pass.MuxToggleCoverage)),
    RunFirrtlTransformAnnotation(Dependency(pass.MetaResetPass)),
    RunFirrtlTransformAnnotation(Dependency(pass.RemovePrintfPass)),
    RunFirrtlTransformAnnotation(Dependency(pass.AssertSignalPass)),
    RunFirrtlTransformAnnotation(Dependency[LowFirrtlEmitter]),
    // if we use verilator, we want to use JNI
    VerilatorUseJNI,
    // debugging output
    // LogLevelAnnotation(LogLevel.Info),
  )


  def firrtlToTarget(filename: String, targetDir: String): FuzzTarget = {
    val state = loadFirrtl(filename, targetDir)
    val info = TopmoduleInfo(state.circuit)
    val dut = TreadleSimulator.createContext(state)
    //val dut = VerilatorSimulator.createContext(state)
    new RfuzzTarget(dut, info)
  }

  private lazy val firrtlStage = new FirrtlStage
  private def loadFirrtl(filename: String, targetDir: String): firrtl.CircuitState = {
    // we need to compile the firrtl file to low firrtl + add mux toggle coverage and meta reset
    val annos = DefaultAnnotations ++ Seq(TargetDirAnnotation(targetDir), FirrtlFileAnnotation(filename))
    val r = firrtlStage.execute(Array(), annos)
    val circuit = r.collectFirst { case FirrtlCircuitAnnotation(c) => c }.get
    firrtl.CircuitState(circuit, r)
  }
}



class RfuzzTarget(dut: SimulatorContext, info: TopmoduleInfo) extends FuzzTarget {
  val MetaReset = "metaReset"
  require(info.clocks.size == 1, s"Only designs with a single clock are supported!\n${info.clocks}")
  require(info.inputs.exists(_._1 == MetaReset), s"No meta reset in ${info.inputs}")
  require(info.inputs.exists(_._1 == "reset"))

  private val clock = info.clocks.head
  private def step(): Unit = {
    dut.step(clock, 1)
    cycles += 1
  }
  private var cycles: Long = 0
  private var resetCycles: Long = 0
  private var totalTime: Long = 0
  private var coverageTime: Long = 0

  private def setInputsToZero(): Unit = {
    info.inputs.foreach { case (n, _) => dut.poke(n, 0)}
  }

  private def metaReset(): Unit = {
    dut.poke(MetaReset, 1)
    step()
    dut.poke(MetaReset, 0)
    resetCycles += 1
  }

  private def reset(): Unit = {
    dut.poke("reset", 1)
    step()
    dut.poke("reset", 0)
    resetCycles += 1
  }

  private val inputBits = info.inputs.map(_._2).sum
  private val inputSize = scala.math.ceil(inputBits.toDouble / 8.0).toInt

  private def pop(input: java.io.InputStream): Array[Byte] = {
    val r = input.readNBytes(inputSize)
    if(r.size == inputSize) { r } else { Array.emptyByteArray }
  }

  private def getCoverage(): Seq[Byte] = {
    dut.getCoverage().map(_._2).map(v => scala.math.min(v, 255).toByte)
  }

  private val fuzzInputs = info.inputs.filterNot{ case (n, _) => n == MetaReset || n == "reset" }
  private def applyInputs(bytes: Array[Byte]): Unit = {
    var input: BigInt = bytes.zipWithIndex.map { case (b, i) =>  BigInt(b) << (i * 8) }.reduce(_ | _)
    fuzzInputs.foreach { case (name, bits) =>
      val mask = (BigInt(1) << bits) - 1
      val value = input & mask
      input = input >> bits
      dut.poke(name, value)
    }
  }

  override def run(input: java.io.InputStream): Seq[Byte] = {
    val start = System.nanoTime()
    setInputsToZero()
    metaReset()
    reset()
    // we only consider coverage _after_ the reset is done!
    dut.resetCoverage()

    var inputBytes = pop(input)
    while(inputBytes.nonEmpty) {
      applyInputs(inputBytes)
      step()
      inputBytes = pop(input)
    }

    val startCoverage = System.nanoTime()
    val c = getCoverage()
    val end = System.nanoTime()
    totalTime += (end - start)
    coverageTime += (end - startCoverage)
    c
  }

  private def ms(i: Long): Long = i / 1000 / 1000
  override def finish(verbose: Boolean): Unit = {
    dut.finish()
    if(verbose) {
      println(s"Executed $cycles target cycles (incl. $resetCycles reset cycles).")
      println(s"Total time in simulator: ${ms(totalTime)}ms")
      println(s"Total time for getCoverage: ${ms(coverageTime)}ms (${coverageTime.toDouble / totalTime.toDouble * 100.0}%)")
      val MHz = cycles.toDouble * 1000.0 / totalTime.toDouble
      println(s"$MHz MHz")
    }
  }
}