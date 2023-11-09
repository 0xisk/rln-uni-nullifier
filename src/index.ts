import { RLNProver, RLNVerifier } from "rlnjs";
import { fieldFactory, generateMerkleProof, rlnParams } from "./utils";
import { DEFAULT_MERKLE_TREE_DEPTH, calculateIdentityCommitment } from "./common";

const LIMIT_BIT_SIZE = 16;

const rlnProver = new RLNProver(rlnParams.wasmFilePath, rlnParams.finalZkeyPath);
const rlnVerifier = new RLNVerifier(rlnParams.verificationKey);

const rlnIdentifier = fieldFactory();
console.log("rlnIdentifier", rlnIdentifier);

const identitySecret = fieldFactory();
console.log("identitySecret", identitySecret);

const identityCommitment = calculateIdentityCommitment(identitySecret);
console.log("identityCommitment", identityCommitment);

const leaves = [identityCommitment];
console.log("leaves", leaves);

const userMessageLimit = BigInt(1);
console.log("userMessageLimit", userMessageLimit);

const x = fieldFactory();
console.log("x", x);

const epoch = fieldFactory();
console.log("epoch", epoch);

const treeDepth = DEFAULT_MERKLE_TREE_DEPTH;
console.log("treeDepth", treeDepth);

const checkGenerationValidProof = async (): Promise<boolean> => {
    const m0 = performance.now();
    const merkleProof = generateMerkleProof(rlnIdentifier, leaves, treeDepth, 0);
    const m1 = performance.now();

    const messageId = BigInt(0);
    console.log("messageId", messageId);

    const proof = await rlnProver.generateProof({
        rlnIdentifier,
        identitySecret,
        userMessageLimit,
        messageId,
        merkleProof,
        x,
        epoch
    });
    const m2 = performance.now();
    const isValid = await rlnVerifier.verifyProof(rlnIdentifier, proof);
    const m3 = performance.now();
    console.log(`Merkle proof generation: ${m1 - m0} ms`);
    console.log(`RLN proof generation: ${m2 - m1} ms`);
    console.log(`RLN proof verification: ${m3 - m2} ms`);

    return isValid;
}

const checkGenerationInvalidProof = async (): Promise<boolean> => {
    const m0 = performance.now();
    const merkleProof = generateMerkleProof(rlnIdentifier, leaves, treeDepth, 0);
    const m1 = performance.now();

    const messageId = BigInt(0);
    console.log("messageId", messageId);

    const proof = await rlnProver.generateProof({
        rlnIdentifier,
        identitySecret,
        userMessageLimit,
        messageId,
        merkleProof,
        x,
        epoch
    });
    const m2 = performance.now();
    const isValid = await rlnVerifier.verifyProof(rlnIdentifier, proof);
    const m3 = performance.now();
    console.log(`Merkle proof generation: ${m1 - m0} ms`);
    console.log(`RLN proof generation: ${m2 - m1} ms`);
    console.log(`RLN proof verification: ${m3 - m2} ms`);

    return isValid;
}

const oneValidation = async () => {
    const valid = await checkGenerationValidProof();
    const inValid = await checkGenerationInvalidProof();

    console.log("valid", valid);
    console.log("inValid", inValid);
}

oneValidation()
.then();

