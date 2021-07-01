/*
 * Copyright (c) 2017-2021 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


package chiseltest.fuzzing.afl

/** Provides a main function that can be used to interface with the AFL fuzzer.
 *
 *  Based on code written by Rohan Padhye for the JQF project
 * */
object AFLDriver extends App {
  def usage = "Usage: java " + this.getClass + " TEST_CLASS TEST_METHOD TEST_INPUT_FILE AFL_TO_JAVA_PIPE JAVA_TO_AFL_PIPE"
  require(args.length == 5, usage)

}

/**
 * A front-end that uses AFL for guided fuzzing.
 *
 * An instance of this class actually communicates with a proxy that
 * sits between AFL and JQF. The proxy is the target program launched by
 * AFL; it passes messages back and forth between AFL and JQF and
 * helps populate the shared memory coverage buffer that the JVM cannot
 * access.
 *
 * @author Rohan Padhye and Caroline Lemieux (adapted to Scala by Kevin Laeufer)
 */
private class AFLGuidance(inputFile: os.Path, inPipe: os.Path, outPipe: os.Path) {

}