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
// TODO: filter out duplicates!
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
      mod.mapStmt(onStmt(ctx, _))
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

  private def onStmt(ctx: ModuleCtx, s: ir.Statement): ir.Statement = s match {
    case ir.Block(stmts) => ir.Block(stmts.map(onStmt(ctx, _)))
    case other =>
      val stmts = mutable.ListBuffer[ir.Statement]()
      val r = other.mapExpr(onExpr(ctx, stmts, _))
      if(stmts.isEmpty) { r } else {
        stmts.append(r)
        ir.Block(stmts.toList)
      }
  }

  private def onExpr(ctx: ModuleCtx, stmts: mutable.ListBuffer[ir.Statement], e: ir.Expression): ir.Expression =
    e.mapExpr(onExpr(ctx, stmts, _)) match {
      case m @ ir.Mux(cond, _, _, _) =>
        // ensure that we get a reference to the condition (this avoids duplicated code)
        val condRef = cond match {
          case r: ir.Reference => r
          case other =>
            val node = ir.DefNode(ir.NoInfo, ctx.namespace.newName("mux_cond"), other)
            stmts.append(node)
            ir.Reference(node).copy(flow = SourceFlow)
        }
        coverToggle(ctx, stmts, condRef)
        m.copy(cond = condRef)
      case other => other
    }

  private def coverToggle(ctx: ModuleCtx, stmts: mutable.ListBuffer[ir.Statement], cond: ir.Reference): Unit = {
    // TODO: add annotation
    val target = ctx.m.ref(cond.name)

    val oneCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, cond, Utils.not(ctx.reset), ir.StringLit(""), ctx.namespace.newName(cond.name + "_one"))
    stmts.append(oneCover)
    val zeroCover = ir.Verification(ir.Formal.Cover, ir.NoInfo, ctx.clock, Utils.not(cond), Utils.not(ctx.reset), ir.StringLit(""), ctx.namespace.newName(cond.name + "_zero"))
    stmts.append(zeroCover)
  }

}
