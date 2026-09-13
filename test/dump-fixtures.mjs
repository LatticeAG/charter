/** Dump the §11.1 fixture corpus to JSON for the Python differential run. */
import * as fx from "../fixtures/corpus.ts";
import { writeFileSync } from "node:fs";

const data = {
  SEEDS: fx.SEEDS, T: fx.T, C: fx.C, G: fx.G, I: fx.I, A: fx.A, O: fx.O, L: fx.L,
  KA: fx.KA, KB: fx.KB, KC: fx.KC, CR: fx.CR, RA: fx.RA, RD: fx.RD,
  T0: fx.T0, T30: fx.T30, T180: fx.T180, T300: fx.T300, END: fx.END,
  AUTH: fx.AUTH, ROOT: fx.ROOT, M1: fx.M1, MH: fx.MH,
  C1: fx.C1, H1: fx.H1, C2: fx.C2, H2: fx.H2, P1: fx.P1, P2: fx.P2,
  B1: fx.B1, B2: fx.B2, pc: fx.pc, U1: fx.U1, PUBLISH1: fx.PUBLISH1,
  PRINCIPAL: fx.PRINCIPAL, Q1: fx.Q1, ALLOW: fx.ALLOW, EI1: fx.EI1,
  IH1: fx.IH1, OH1: fx.OH1, DEP: fx.DEP, HB1: fx.HB1, FLEET1: fx.FLEET1,
  CITE1: fx.CITE1, VALID1: fx.VALID1, PAUSE1: fx.PAUSE1, REVOKE1: fx.REVOKE1,
  REV1: fx.REV1, DR1: fx.DR1, DISPUTE1: fx.DISPUTE1, SUCCESS1: fx.SUCCESS1,
  AR1: fx.AR1, EB1: fx.EB1, E1: fx.E1, CPB1: fx.CPB1, CP1: fx.CP1,
  EV1: fx.EV1, VERIFY1: fx.VERIFY1, METRICS1: fx.METRICS1, RFC_SIG: fx.RFC_SIG,
};
writeFileSync(process.argv[2] ?? "/tmp/charter-fixtures.json", JSON.stringify(data));
console.log(process.argv[2] ?? "/tmp/charter-fixtures.json");
