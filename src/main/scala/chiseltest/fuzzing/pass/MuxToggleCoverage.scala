// Copyright 2017-2021 The Regents of the University of California
// released under BSD 3-Clause License
// author: Jack Koenig <koenig@sifive.com>, Kevin Laeufer <laeufer@cs.berkeley.edu>

package chiseltest.fuzzing.pass

import firrtl._
import firrtl.annotations._
import firrtl.options.Dependency

import scala.collection.mutable

// adds mux toggle coverage with a coverage statement
// see: https://people.eecs.berkeley.edu/~laeufer/papers/rfuzz_kevin_laeufer_iccad2018.pdf
// TODO: this transform should build upon the standard toggle coverage pass once that is published + polished!
object MuxToggleCoverage extends Transform with DependencyAPIMigration {
  override def prerequisites = Seq(
    Dependency[firrtl.transforms.RemoveWires], Dependency(passes.ExpandWhens), Dependency(passes.LowerTypes)
  )
  override def invalidates(a: Transform) = false

  override def execute(state: CircuitState): CircuitState = {
    // TODO: add support for standard annotation to skip modules

    val c = CircuitTarget(state.circuit.main)
    val newAnnos = mutable.ListBuffer[Annotation]()
    val circuit = state.circuit.mapModule(onModule(_, c, newAnnos))
    state.copy(circuit = circuit, annotations = newAnnos.toList ++: state.annotations)
  }

  private def onModule(m: ir.DefModule, c: CircuitTarget, newAnnos: mutable.ListBuffer[Annotation]): ir.DefModule = m match {
    case mod: ir.Module =>
      val ctx = ModuleCtx(c.module(mod.name), Namespace(mod), newAnnos, findClock(mod), findReset(mod))
      val conds = findMuxConditions(mod)
      val (stmts, annos) = coverToggle(ctx, conds)
      assert(annos.isEmpty)
      mod.copy(body = ir.Block(mod.body +: stmts))
    case other => other
  }

  // TODO: replace with library function
  private def findClock(m: ir.Module): ir.Expression = {
    m.ports.collectFirst { case p @ ir.Port(_, _, ir.Input, ir.ClockType) => ir.Reference(p) }.getOrElse(
      throw new RuntimeException(s"Couldn't find a clock input for:\n${m.serialize}")
    )
  }

  // TODO: replace with library function
  private def findReset(m: ir.Module): ir.Expression = {
    m.ports.find(_.name == "reset").map(p => ir.Reference(p)).getOrElse(
      throw new RuntimeException(s"Couldn't find a clock input for:\n${m.serialize}")
    )
  }

  private case class ModuleCtx(m: ModuleTarget, namespace: Namespace, newAnnos: mutable.ListBuffer[Annotation],
    clock: ir.Expression, reset: ir.Expression)


  private def coverToggle(ctx: ModuleCtx, conds: List[ir.Expression]): (List[ir.Statement], List[Annotation]) = {
    val stmts = conds.flatMap { cond =>
      val name = cond match {
        case ir.Reference(name, _, _, _) => name
        case _ => "mux_cond"
      }
      val oneCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, cond, Utils.not(ctx.reset),
        ir.StringLit(""), ctx.namespace.newName(name + "_one"))
      val zeroCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, Utils.not(cond), Utils.not(ctx.reset),
        ir.StringLit(""), ctx.namespace.newName(name + "_zero"))
      List(oneCover, zeroCover)
    }
    (stmts, List())
  }

  // returns a list of unique (at least structurally unique!) mux conditions used in the module
  private def findMuxConditions(m: ir.Module): List[ir.Expression] = {
    val conds = mutable.LinkedHashMap[String, ir.Expression]()

    def onStmt(s: ir.Statement): Unit = s match {
      case ir.Block(stmts) => stmts.foreach(onStmt)
      case other => other.foreachExpr(onExpr)
    }
    def onExpr(e: ir.Expression): Unit = {
      e.foreachExpr(onExpr)
      e match {
        case ir.Mux(cond, _, _, _) =>
          val key = cond.serialize
          conds(key) = cond
        case _ =>
      }
    }
    onStmt(m.body)
    conds.values.toList
  }
}
