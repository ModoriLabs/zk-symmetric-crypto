import { UltraHonkBackend } from '@aztec/bb.js'
// @ts-ignore
import { CompiledCircuit, Noir } from '@noir-lang/noir_js'
import {
	BarretenbergOperator,
	Logger,
	MakeZKOperatorOpts,
	ZKProofInput,
	ZKProofPublicSignals,
} from '../types'
import { BarretenbergOpts } from './types'
import { convertToNoirWitness, getCircuitFilename } from './utils'

/**
 * Creates a Barretenberg ZK operator for Noir circuits
 * This operator uses the UltraHonk proving system from Barretenberg
 */
export function makeBarretenbergZKOperator({
	algorithm,
	fetcher,
	options: { threads = 1 } = {}
}: MakeZKOperatorOpts<BarretenbergOpts>): BarretenbergOperator {
	let circuit: CompiledCircuit
	let noir: Noir
	let backend: UltraHonkBackend

	async function loadCircuit(logger?: Logger): Promise<CompiledCircuit> {
		if(!circuit) {
			logger?.info?.(`Loading Noir circuit for ${algorithm}`)
			const circuitData = await fetcher.fetch(
				'barretenberg',
				getCircuitFilename(algorithm),
				logger
			)
			circuit = JSON.parse(new TextDecoder().decode(circuitData)) as CompiledCircuit
			logger?.info?.('Circuit loaded successfully')
		}

		return circuit
	}

	async function initializeBackend(logger?: Logger): Promise<{ noir: Noir, backend: UltraHonkBackend }> {
		if(!noir || !backend) {
			const loadedCircuit = await loadCircuit(logger)
			noir = new Noir(loadedCircuit)
			backend = new UltraHonkBackend(loadedCircuit.bytecode, { threads })
			logger?.info?.(`Barretenberg backend initialized with ${threads} threads`)
		}

		return { noir, backend }
	}

	return {
		async generateWitness(input: ZKProofInput, logger?: Logger): Promise<Uint8Array> {
			const { noir: noirInstance } = await initializeBackend(logger)

			// Convert input to Noir witness format
			const noirInput = convertToNoirWitness(algorithm, input)
			// console.log('noirInput', JSON.stringify(noirInput, null, 2))

			logger?.debug?.('Executing Noir circuit...')

			const tempNoirInput = {
				key: [
					96, 61, 235, 16, 21, 202, 113, 190,
					43, 115, 174, 240, 133, 125, 119, 129,
					31, 53, 44, 7, 59, 97, 8, 215,
					45, 152, 16, 163, 9, 20, 223, 244
				],
				counter: [
					240, 241, 242, 243,
					244, 245, 246, 247,
					248, 249, 250, 251,
					252, 253, 254, 255
				],
				plaintext: [
					107, 193, 190, 226, 46, 64, 159, 150, 233, 61, 126, 17,
					115, 147, 23, 42, 174, 45, 138, 87, 30, 3, 172, 156,
					158, 183, 111, 172, 69, 175, 142, 81, 48, 200, 28, 70,
					163, 92, 228, 17, 229, 251, 193, 25, 26, 10, 82, 239,
					246, 159, 36, 69, 223, 79, 155, 23, 173, 43, 65, 123,
					230, 108, 55, 16, 1, 35, 69, 103, 137, 1, 35, 69,
					103, 137, 1, 35, 69, 103, 137, 1
				],
				expected_ciphertext: [
					 96, 30, 195, 19, 119, 87, 137, 165, 183, 167, 245, 4,
					187, 243, 210, 40, 244, 67, 227, 202, 77, 98, 181, 154,
					202, 132, 233, 144, 202, 202, 245, 197, 43, 9, 48, 218,
					162, 61, 233, 76, 232, 112, 23, 186, 45, 132, 152, 141,
					223, 201, 197, 141, 182, 122, 173, 166, 19, 194, 221, 8,
					 69, 121, 65, 166, 138, 84, 186, 135, 80, 125, 42, 215,
					176, 126, 15, 63, 172, 168, 74, 182
				]
			}
			console.log('noirInput', noirInput)
			console.log('tempNoirInput', tempNoirInput)


			// const { witness } = await noirInstance.execute(noirInput)
			const { witness } = await noirInstance.execute(tempNoirInput)
			console.log('witness', witness)
			// console.log('witness length', witness.length)

			logger?.debug?.('Witness generated successfully')
			return witness
		},

		async ultrahonkProve(witness: Uint8Array, logger?: Logger): Promise<{ proof: Uint8Array }> {
			const { backend: backendInstance } = await initializeBackend(logger)
			console.log('backendInstance', backendInstance)
			console.log('witness', witness)

			logger?.info?.('Generating proof with UltraHonk backend...')
			const startTime = Date.now()

			const proofData = await backendInstance.generateProof(witness)
			console.log('proofData', proofData)
			const proofTime = Date.now() - startTime
			logger?.info?.(`Proof generated in ${proofTime}ms, size: ${proofData.proof.length} bytes`)

			// Store the full proof data (including public inputs) in the proof bytes
			// We'll need to reconstruct this for verification
			const fullProof = {
				proof: Array.from(proofData.proof),
				publicInputs: proofData.publicInputs
			}
			console.log('fullPoof', fullProof)
			const proofBytes = new TextEncoder().encode(JSON.stringify(fullProof))

			return { proof: proofBytes }
		},

		async ultrahonkVerify(
			publicSignals: ZKProofPublicSignals,
			proof: Uint8Array | string,
			logger?: Logger
		): Promise<boolean> {
			const { backend: backendInstance } = await initializeBackend(logger)
			logger?.info?.('Verifying proof with UltraHonk backend...')
			const startTime = Date.now()

			try {
				// Parse the proof data from the encoded bytes
				const proofBytes = typeof proof === 'string'
					? new Uint8Array(Buffer.from(proof, 'hex'))
					: proof
				const fullProof = JSON.parse(new TextDecoder().decode(proofBytes))
				const proofData = {
					proof: new Uint8Array(fullProof.proof),
					publicInputs: fullProof.publicInputs
				}

				const isValid = await backendInstance.verifyProof(proofData)

				const verifyTime = Date.now() - startTime
				logger?.info?.(`Proof verification completed in ${verifyTime}ms, result: ${isValid}`)

				return isValid
			} catch(error) {
				logger?.error?.(`Proof verification failed: ${error}`)
				// console.error('Verification error details:', error)
				return false
			}
		}
	}
}
