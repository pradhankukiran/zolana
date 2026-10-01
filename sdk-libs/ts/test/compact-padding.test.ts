import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { createCompactTransferInput, prepareTransfer } from "../src/client/prover/assembly.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Merge,
  PreparedMerge,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createProofOutput,
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
    // Compact padding publishes nullifier 0, so the prover fetches no
    // non-inclusion proof for it, where a random dummy publishes its own.
    const assembly = prepareTransfer(signed);
    expect(assembly.inputs.payload.inputs.map((input) => input.nullifier === 0n)).toEqual([
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

  it("refuses a slot after compact padding on either side", () => {
    const sender = ShieldedKeypair.generate();
    const signed = ConfidentialTransfer.compact(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      PAYER,
    )
      .withShape({ inputs: 3, outputs: 3 })
      .sign(sender, new AssetRegistry());
    const [real, compactInput] = signed.inputUtxos;
    const [change, compactOutput] = signed.outputs;
    if (!real || !compactInput || !change || !compactOutput) expect.unreachable();
    const rebuilt = (
      slots: Readonly<{ inputUtxos?: readonly ProofInputUtxo[]; outputs?: typeof signed.outputs }>,
    ) =>
      new SppProofInputs({
        payer: signed.payer,
        inputUtxos: slots.inputUtxos ?? signed.inputUtxos,
        outputs: slots.outputs ?? signed.outputs,
        externalData: signed.externalData,
        blindingSeed: signed.blindingSeed,
        outputTreeId: signed.outputTreeId,
      });

    expect(() =>
      rebuilt({ inputUtxos: [real, compactInput, ProofInputUtxo.dummy(undefined, real.treeId)] }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "input", index: 2 },
      }),
    );
    const randomDummy = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: randomBlinding(),
      ownerTag: new Uint8Array(32).fill(8) as Bytes32,
    });
    expect(() => rebuilt({ outputs: [change, compactOutput, randomDummy] })).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "output", index: 2 },
      }),
    );
  });

  it("gives compact padding the zero witness under tree slot 0", () => {
    const witness = createCompactTransferInput(ProofInputUtxo.compact(5), 0);

    expect({
      isDummy: witness.isDummy,
      treeSlot: witness.treeSlot,
      nullifier: witness.nullifier,
      ownerPublicKeyHash: witness.ownerPublicKeyHash,
      nullifierSecret: witness.nullifierSecret,
      statePathIndex: witness.statePathIndex,
      nullifierLowValue: witness.nullifierLowValue,
      nullifierNextValue: witness.nullifierNextValue,
      nullifierLowPathIndex: witness.nullifierLowPathIndex,
    }).toEqual({
      isDummy: 1n,
      treeSlot: 0n,
      nullifier: 0n,
      ownerPublicKeyHash: 0n,
      nullifierSecret: 0n,
      statePathIndex: 0n,
      nullifierLowValue: 0n,
      nullifierNextValue: 0n,
      nullifierLowPathIndex: 0n,
    });
    expect(witness.statePathElements).toEqual(Array<bigint>(32).fill(0n));
    expect(witness.nullifierLowPathElements).toEqual(Array<bigint>(40).fill(0n));
  });

  it("refuses a prepared merge whose compact padding SPP would read differently", () => {
    const owner = ShieldedKeypair.generate();
    const inputs = [solInput(owner, 2n), solInput(owner, 3n), solInput(owner, 4n)];
    const prepared = Merge.fromKeypair(owner, inputs, undefined, { compact: true }).prepare();
    const rebuilt = (padded: readonly ProofInputUtxo[], dummyNullifiers: readonly Bytes32[]) =>
      new PreparedMerge({
        inputs: padded,
        output: prepared.output,
        expiryUnixTs: prepared.expiryUnixTs,
        signingPublicKey: prepared.signingPublicKey,
        nullifierPublicKey: prepared.nullifierPublicKey,
        dummyNullifiers,
        privateTxBlinding: prepared.privateTxBlinding(),
        outputTreeId: prepared.outputTreeId,
      });
    const compact = () => ProofInputUtxo.compact(prepared.inputTreeId);

    // A dummy after compact padding: SPP moves the zero past it.
    const reordered = [
      ...inputs,
      compact(),
      ProofInputUtxo.dummy(undefined, prepared.inputTreeId),
      compact(),
      compact(),
      compact(),
    ];
    expect(() => rebuilt(reordered, [new Uint8Array(32).fill(1) as Bytes32])).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "input", index: 4 },
      }),
    );
    // Three sent nullifiers select the 8-input circuit, not the 36-input one.
    const tooWide = [...inputs, ...Array.from({ length: 33 }, compact)];
    expect(() => rebuilt(tooWide, [])).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_UNSUPPORTED_SHAPE",
        details: { inputs: 36, sent: 3 },
      }),
    );
  });

  it("refuses compact padding on a ring merge", () => {
    const owner = ShieldedKeypair.generate();
    const first = solInput(owner, 2n);
    expect(
      () =>
        new Merge({
          address: owner.shieldedAddress(),
          inputs: [first],
          outputBlinding: randomBlinding(),
          privateTxBlinding: randomBlinding(),
          dummyNullifiers: [],
          ring: { programId: PAYER },
          compact: true,
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_RING_MERGE_COMPACT_PADDING" }));
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
