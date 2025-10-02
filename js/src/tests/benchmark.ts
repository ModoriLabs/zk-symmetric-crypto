import { randomBytes } from 'crypto'
import { Bench } from 'tinybench'
import { CONFIG } from '../config'
import { BarretenbergOperator, EncryptionAlgorithm, isBarretenbergOperator, PrivateInput, PublicInput, Proof, ZKOperator } from '../types'
import { generateZkWitness, getPublicSignals } from '../zk'
import { encryptData, ZK_CONFIG_MAP, ZK_CONFIGS } from './utils'

const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	//'aes-256-ctr',
	//'aes-128-ctr',
]

const DATA_LENGTH = 1024

const BENCHES = ALL_ALGOS.map((algo) => {
	let bench = new Bench({
		name: `Generate Proof - ${algo}`,
		iterations: 1,
	})

	for(const engine of ZK_CONFIGS) {
		const operator = ZK_CONFIG_MAP[engine](algo)
		let testData: Array<{ witness: Uint8Array, publicInput: PublicInput, plaintext: Uint8Array }>
		bench = bench.add(
			engine,
			async() => {
				try {
					const now = Date.now()
					const proofs = await Promise.all(
						testData.map(({ witness }) => {
							if(isBarretenbergOperator(operator)) {
								return operator.ultrahonkProve(witness)
							} else {
								return operator.groth16Prove(witness)
							}
						})
					)
					const elapsed = Date.now() - now
					console.log(
						`Generated ${testData.length} proofs for ${algo} using ${engine}, ${elapsed}ms`
					)

					// Verify all proofs
					const verifyStart = Date.now()
					const verifications = await Promise.all(
						proofs.map((proofResult, i) => {
							const { publicInput, plaintext } = testData[i]
							const proof: Proof = {
								algorithm: algo,
								proofData: proofResult.proof,
								plaintext
							}
							const publicSignals = getPublicSignals({ proof, publicInput })

							if(isBarretenbergOperator(operator)) {
								return operator.ultrahonkVerify(publicSignals, proofResult.proof)
							} else {
								return operator.groth16Verify(publicSignals, proofResult.proof)
							}
						})
					)
					const verifyElapsed = Date.now() - verifyStart

					const allValid = verifications.every(v => v)
					console.log(
						`Verified ${proofs.length} proofs for ${algo} using ${engine}, ${verifyElapsed}ms, all valid: ${allValid}`
					)
				} catch(err) {
					console.error(err)
				}
			},
			{
				beforeEach: async() => {
					testData = await prepareDataForAlgo(algo, operator)
					console.log(
						`Prepared ${testData.length} witnesses for ${algo} using ${engine}`
					)
				},
			}
		)
	}

	return bench
})

async function main() {
	for(const bench of BENCHES) {
		await bench.run()

		console.log(bench.name)
		console.table(bench.table())
	}
}

async function prepareDataForAlgo(
	algo: EncryptionAlgorithm,
	operator: ZKOperator | BarretenbergOperator
) {
	const { keySizeBytes, chunkSize, bitsPerWord } = CONFIG[algo]
	const plaintext = new Uint8Array(randomBytes(DATA_LENGTH))
	const privateInput: PrivateInput = {
		key: Buffer.alloc(keySizeBytes, 2),
	}

	const iv = new Uint8Array(12).fill(0)

	const ciphertext = encryptData(
		algo,
		plaintext,
		privateInput.key,
		iv
	)

	const testData: Array<{ witness: Uint8Array, publicInput: PublicInput, plaintext: Uint8Array }> = []
	const chunkSizeBytes = chunkSize * bitsPerWord / 8

	for(let i = 0; i < ciphertext.length; i += chunkSizeBytes) {
		const publicInput: PublicInput = {
			ciphertext: ciphertext.subarray(i, i + chunkSizeBytes),
			iv: iv,
			offsetBytes: i
		}
		const { witness, plaintextArray } = await generateZkWitness({
			algorithm: algo,
			privateInput,
			publicInput
		})

		const wtnsSerialised = await operator.generateWitness(witness)

		testData.push({
			witness: wtnsSerialised,
			publicInput,
			plaintext: plaintextArray
		})
	}

	return testData
}

main()

