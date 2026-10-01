import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { prepareTransfer } from "../src/client/prover/assembly.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Merge,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  transactOutputBlinding,
} from "../src/transaction/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

function solInput(keypair: ShieldedKeypair, amount: bigint): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: randomBlinding(),
    }),
    keypair,
  );
}

describe("compact padding", () => {
  it("pads a transfer with compact slots that stay out of the instruction", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const transfer = ConfidentialTransfer.compact(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      PAYER,
    ).withShape({ inputs: 2, outputs: 3 });
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);
    const prepared = transfer.prepare();
    const signed = transfer.sign(sender, new AssetRegistry());

    expect(signed.inputUtxos.map((input) => input.isCompact())).toEqual([false, true]);
    expect(signed.inputUtxos[1]?.nullifier()).toEqual(new Uint8Array(32));
    expect(signed.outputs.map((output) => output.isCompact())).toEqual([false, false, true]);
    expect(signed.outputs[2]?.hash(signed.outputTreeId)).toEqual(new Uint8Array(32));
    expect(signed.outputs[2]?.blinding).toEqual(
      transactOutputBlinding(prepared.firstNullifier, prepared.outputBlindingSeed(), 2),
    );
    expect([
      signed.externalData.outputs.length,
      signed.externalData.resolvedOwnerTags.length,
    ]).toEqual([2, 2]);
    expect(signed.dummyNullifiers()).toEqual([]);
    expect(signed.checkShape()).toEqual({ inputs: 2, outputs: 3 });

    // The instruction carries only the sent slots; SPP fills the rest back in.
    const assembly = prepareTransfer(signed);
    expect(assembly.inputs.lookups.map((lookup) => lookup.commitment === null)).toEqual([
      false,
      true,
    ]);
    const treeId = signed.inputUtxos[0]?.treeId ?? 0;
    const { instructionData } = assembly.finish([
      {
        treeId,
        slot: {
          id: treeId,
          utxoRoot: new Uint8Array(32).fill(1) as Bytes32,
          nullifierRoot: new Uint8Array(32).fill(2) as Bytes32,
        },
        utxoRootIndex: 0,
        nullifierRootIndex: 0,
      },
    ]);
    expect([instructionData.inputs.length, instructionData.outputs.length]).toEqual([1, 2]);
  });

  it("pads a merge with compact slots and derives no dummy nullifiers", () => {
    const owner = ShieldedKeypair.generate();
    const inputs = [solInput(owner, 2n), solInput(owner, 3n), solInput(owner, 4n)];
    const prepared = Merge.fromKeypair(owner, inputs, undefined, { compact: true }).prepare();

    expect(prepared.inputs).toHaveLength(8);
    expect(prepared.inputs.slice(inputs.length).every((input) => input.isCompact())).toBe(true);
    expect(prepared.dummyNullifiers()).toEqual([]);
    expect(prepared.output.amount).toBe(9n);
  });
});
