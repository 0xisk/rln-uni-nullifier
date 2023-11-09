import * as fs from "fs";
import * as path from "path";
import { type VerificationKey } from "rlnjs";
import { IncrementalMerkleTree, MerkleProof } from "@zk-kit/incremental-merkle-tree"
import { poseidon2 } from "poseidon-lite";
import { zeroPad } from '@ethersproject/bytes'
import { BigNumber } from '@ethersproject/bignumber'
import { keccak256 } from '@ethersproject/keccak256'

import { Fq } from "./common"

const thisFileDirname = __dirname

function parseVerificationKeyJSON(json: string): VerificationKey {
    const o = JSON.parse(json)
    // NOTE: This is not a complete check, to do better we can check values are of the correct type
    if (!o.protocol) throw new Error('Verification key has no protocol')
    if (!o.curve) throw new Error('Verification key has no curve')
    if (!o.nPublic) throw new Error('Verification key has no nPublic')
    if (!o.vk_alpha_1) throw new Error('Verification key has no vk_alpha_1')
    if (!o.vk_beta_2) throw new Error('Verification key has no vk_beta_2')
    if (!o.vk_gamma_2) throw new Error('Verification key has no vk_gamma_2')
    if (!o.vk_delta_2) throw new Error('Verification key has no vk_delta_2')
    if (!o.vk_alphabeta_12) throw new Error('Verification key has no vk_alphabeta_12')
    if (!o.IC) throw new Error('Verification key has no IC')
    return o
}

function getParamsPath(paramsDir: string) {
    const verificationKeyPath = path.join(paramsDir, "rln.json")
    return {
        wasmFilePath: path.join(paramsDir, "rln.wasm"),
        finalZkeyPath: path.join(paramsDir, "rln.zkey"),
        verificationKey: parseVerificationKeyJSON(fs.readFileSync(verificationKeyPath, "utf-8")),
    }
}

export const rlnParams = getParamsPath(
    path.join(thisFileDirname, "..", "zkeyFiles", "rln")
)

export function fieldFactory(excludes?: bigint[], trials: number = 100): bigint {
    if (excludes) {
        for (let i = 0; i < trials; i++) {
            const epoch = Fq.random()
            if (!excludes.includes(epoch)) {
                return epoch
            }
        }
        throw new Error("Failed to generate a random epoch")
    } else {
        return Fq.random()
    }
}


function calculateZeroValue(id: bigint): bigint {
    const hexStr = BigNumber.from(id).toTwos(256).toHexString()
    const zeroPadded = zeroPad(hexStr, 32)
    return BigInt(keccak256(zeroPadded)) >> BigInt(8)
}

export function verifyMerkleProof(rlnIdentifier: bigint, proof: MerkleProof, treeDepth: number) {
    const zeroValue = calculateZeroValue(rlnIdentifier)
    const tree = new IncrementalMerkleTree(poseidon2, treeDepth, zeroValue, 2)
    proof.siblings = proof.siblings.map((s) => [s])
    return tree.verifyProof(proof)
}

export function generateMerkleProof(rlnIdentifier: bigint, leaves: bigint[], treeDepth: number, index: number) {
    const zeroValue = calculateZeroValue(rlnIdentifier)
    const tree = new IncrementalMerkleTree(poseidon2, treeDepth, zeroValue, 2)
    for (const leaf of leaves) {
        tree.insert(leaf)
    }
    return tree.createProof(index)
}
