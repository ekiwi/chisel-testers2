// SPDX-License-Identifier: Apache-2.0

package chiseltest.legacy.backends.verilator

import chiseltest.coverage.{Coverage, ModuleInstancesAnnotation, ModuleInstancesPass}
import firrtl._
import firrtl.annotations._
import firrtl.options.Dependency
import firrtl.passes.InlineInstances
import firrtl.stage.{Forms, RunFirrtlTransformAnnotation}
import firrtl.stage.TransformManager.TransformDependency
import firrtl.transforms.EnsureNamedStatements

import java.nio.file._
import scala.io.Source
import scala.collection.mutable

/** Verilator generates a `coverage.dat` file with one entry for every cover statement.
  * Unfortunately the unique name of the coverage statement gets lost, however, since the
  * (System)Verilog emitter maintains the order of the coverage statements, we can just
  * sort them by line number and compare them to the coverage statements in LoFirrtl.
  */
object VerilatorCoverage {

  // We run these two passes in order to extract enough meta data to be able to
  // map the `coverage.dat` generated by Verilator to the cover points in the firrtl design.
  val CoveragePasses = Seq(
    RunFirrtlTransformAnnotation(Dependency(ModuleInstancesPass)),
    RunFirrtlTransformAnnotation(Dependency(FindCoverPointsPass)),
    RunFirrtlTransformAnnotation(Dependency(EnsureNamedStatements)) // without names, no cover points
  )

  // besides the common annotations, we also need to output of the FindCoverPointsPass
  def collectCoverageAnnotations(annos: AnnotationSeq): AnnotationSeq = {
    Coverage.collectCoverageAnnotations(annos) ++ annos.collect { case a: OrderedCoverPointsAnnotation => a }
  }

  def loadCoverage(annos: AnnotationSeq, coverageData: Path): List[(String, Long)] = {
    val entries = parseCoverageData(coverageData)
    verilatorCoverageToCoverageMap(entries, annos)
  }

  private def verilatorCoverageToCoverageMap(es: List[CoverageEntry], annos: AnnotationSeq): List[(String, Long)] = {
    // map from module name to an ordered list of cover points in said module
    val coverPoints = annos.collect { case a: OrderedCoverPointsAnnotation => a.target.module -> a.covers }.toMap
    // map from instance path name to the name of the module
    val instToModule = annos.collect { case a: ModuleInstancesAnnotation => a }.toList match {
      case List(anno) => anno.instanceToModule.toMap
      case other      => throw new RuntimeException(s"Exactly one ModuleInstancesAnnotation is required! Found: $other")
    }

    // process the coverage entries on a per instance basis
    es.groupBy(_.path).toList.flatMap {
      case (name, entries) =>
        // we look up the cover points by first converting to the module name
        val covers = coverPoints(instToModule(name))
        processInstanceCoverage(name, covers, entries)
    }
  }

  private def processInstanceCoverage(
    name:    String,
    covers:  List[String],
    entries: Seq[CoverageEntry]
  ): Seq[(String, Long)] = {
    assert(
      covers.size == entries.size,
      f"[$name] Missing or too many entries! ${covers.size} cover statements vs. ${entries.size} coverage entries."
    )
    covers.zip(entries).map {
      case (c, e) =>
        (if (name.isEmpty) c else name + "." + c) -> e.count
    }
  }

  private def parseCoverageData(coverageData: Path): List[CoverageEntry] = {
    assert(Files.exists(coverageData), f"Could not find coverage file: $coverageData")
    val src = Source.fromFile(coverageData.toString)
    val entries = src.getLines().flatMap(parseLine).toList
    src.close()
    entries.sortBy(_.line)
  }

  // example lines:
  // "C '\x01f\x02Test1Module.sv\x01l\x0240\x01n\x020\x01page\x02v_user/Test1Module\x01o\x02cover\x01h\x02TOP.Test1Module' 3"
  // "C '\x01f\x02Test1Module.sv\x01l\x028\x01n\x020\x01page\x02v_user/SubModule1\x01o\x02cover\x01h\x02TOP.Test1Module.c0' 0"
  // "C '\x01f\x02Test1Module.sv\x01l\x028\x01n\x020\x01page\x02v_user/SubModule1\x01o\x02cover\x01h\x02TOP.Test1Module.c1' 0"
  // output:
  // - CoverageEntry(Test1Module.sv,40,List(),3)
  // - CoverageEntry(Test1Module.sv,8,List(c0),0)
  // - CoverageEntry(Test1Module.sv,8,List(c1),0)
  private def parseLine(line: String): Option[CoverageEntry] = {
    if (!line.startsWith("C '\u0001")) return None
    line.split('\'').toList match {
      case List(_, dict, countStr) =>
        val entries = dict.drop(1).split('\u0001').map(_.split('\u0002').toList).map { case Seq(k, v) => k -> v }.toMap
        val count = countStr.trim.toLong
        val path = entries("h").split('.').toList.drop(2).mkString(".")
        Some(CoverageEntry(file = entries("f"), line = entries("l").toInt, path = path, count = count))
      case _ =>
        throw new RuntimeException(s"Unexpected coverage line format: $line")
    }
  }

  private case class CoverageEntry(file: String, line: Int, path: String, count: Long)
}

/** Generates a list of cover points in each module.
  * This helps us map coverage points as reported by Verilator to
  * the standard coverage map required by the simulator backend interface.
  */
object FindCoverPointsPass extends Transform with DependencyAPIMigration {
  override def prerequisites: Seq[TransformDependency] = Forms.LowForm
  // we needs to run *after* any transform that changes the hierarchy or renames cover points
  override def optionalPrerequisites: Seq[TransformDependency] =
    Seq(Dependency[InlineInstances], Dependency(EnsureNamedStatements))
  // we need to run before the emitter
  override def optionalPrerequisiteOf: Seq[TransformDependency] = Seq(
    Dependency[LowFirrtlEmitter],
    Dependency[VerilogEmitter],
    Dependency[SystemVerilogEmitter]
  )
  override def invalidates(a: Transform): Boolean = false

  override protected def execute(state: CircuitState): CircuitState = {
    val c = CircuitTarget(state.circuit.main)
    val annos = state.circuit.modules.flatMap(onModule(c, _))
    state.copy(annotations = state.annotations ++ annos)
  }

  private def onModule(c: CircuitTarget, m: ir.DefModule): Option[OrderedCoverPointsAnnotation] = m match {
    case _:   ir.ExtModule => None
    case mod: ir.Module =>
      val covs = mutable.ListBuffer[String]()
      mod.foreachStmt(onStmt(_, covs))
      Some(OrderedCoverPointsAnnotation(c.module(mod.name), covs.toList))
  }

  private def onStmt(s: ir.Statement, covs: mutable.ListBuffer[String]): Unit = s match {
    case v: ir.Verification if v.op == ir.Formal.Cover =>
      assert(v.name.nonEmpty)
      covs.append(v.name)
    case other => other.foreachStmt(onStmt(_, covs))
  }
}

case class OrderedCoverPointsAnnotation(target: ModuleTarget, covers: List[String])
    extends SingleTargetAnnotation[ModuleTarget] {
  override def duplicate(n: ModuleTarget) = copy(target = n)
}