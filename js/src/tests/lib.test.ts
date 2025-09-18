import { randomBytes } from 'crypto'
import {
	BarretenbergOperator,
	CONFIG,
	EncryptionAlgorithm,
	generateProof,
	getBlockSizeBytes,
	PrivateInput,
	PublicInput,
	verifyProof,
	ZKEngine,
	ZKOperator,
} from '../index'
import {
	encryptData,
	getEngineForConfigItem,
	ZK_CONFIG_MAP,
	ZK_CONFIGS,
} from './utils'

jest.setTimeout(100_000)

// TODO: add back AES tests
const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	'aes-256-ctr',
	'aes-128-ctr',
]

const SUPPORTED_ALGO_MAP: { [T in ZKEngine]: EncryptionAlgorithm[] } = {
	// TODO: impl more algos for barretenberg
	// barretenberg: ['aes-256-ctr', 'aes-128-ctr'],
	// barretenberg: ['aes-128-ctr', 'chacha20'],
	barretenberg: ['aes-256-ctr'],
	expander: ['chacha20'],
	gnark: ALL_ALGOS,
	snarkjs: ALL_ALGOS,
}

const ALG_TEST_CONFIG: { [E in EncryptionAlgorithm] } = {
	chacha20: {
		encLength: 45,
	},
	'aes-256-ctr': {
		encLength: 44,
	},
	'aes-128-ctr': {
		encLength: 44,
	},
}

describe.each(ZK_CONFIGS)('%s Engine Tests', (zkEngine) => {
	const ALGOS = SUPPORTED_ALGO_MAP[getEngineForConfigItem(zkEngine)]
	if(zkEngine !== 'barretenberg') {
		return
	}

	describe.each(ALGOS)('%s Lib Tests', (algorithm) => {
		console.log('algorithm', algorithm)
		const { encLength } = ALG_TEST_CONFIG[algorithm]
		const { bitsPerWord, chunkSize, keySizeBytes } = CONFIG[algorithm]

		const chunkSizeBytes = (chunkSize * bitsPerWord) / 8

		let operator: ZKOperator | BarretenbergOperator
		beforeAll(async() => {
			operator = await ZK_CONFIG_MAP[zkEngine](algorithm)
		})

		afterEach(async() => {
			await operator.release?.()
		})

		it('should verify encrypted data', async() => {
			// const plaintext = new Uint8Array(randomBytes(encLength))

			// const privateInput: PrivateInput = {
			// 	key: Buffer.alloc(keySizeBytes, 2),
			// }

			const key = new Uint8Array([
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
				0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
				0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
			])

			const plaintext = new Uint8Array([
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
				0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
				0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
				0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
				0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
				0xe6, 0x6c, 0x37, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45,
				0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01,
			])

			const privateInput: PrivateInput = {
				key,
			}

			const iv = new Uint8Array([
				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
			])
			const counter = new Uint8Array([0xfc, 0xfd, 0xfe, 0xff])

			// const iv = new Uint8Array(Array.from(Array(12).keys()))

			console.log('plaintext', plaintext)
			console.log('privateInput', privateInput)

			// const ciphertext = encryptData(
			// 	algorithm,
			// 	plaintext,
			// 	privateInput.key,
			// 	iv
			// )
			// console.log('ciphertext', ciphertext)
			const ciphertext = new Uint8Array([
				96, 30, 195, 19, 119, 87, 137, 165, 183, 167, 245, 4, 187, 243, 210, 40,
				244, 67, 227, 202, 77, 98, 181, 154, 202, 132, 233, 144, 202, 202, 245,
				197, 43, 9, 48, 218, 162, 61, 233, 76, 232, 112, 23, 186, 45, 132, 152,
				141, 223, 201, 197, 141, 182, 122, 173, 166, 19, 194, 221, 8, 69, 121,
				65, 166, 138, 84, 186, 135, 80, 125, 42, 215, 176, 126, 15, 63, 172,
				168, 74, 182,
			])
			const publicInput: PublicInput = { ciphertext, iv: iv }

			const proof = await generateProof({
				algorithm,
				privateInput,
				publicInput,
				operator,
			})
			// client will send proof to witness
			// witness would verify proof
			await verifyProof({ proof, publicInput, operator })
		})

		// it('should verify encrypted with static plaintext', async() => {
		// 	// 76,  97, 100, 105, 101, 115,  32,  97,
		// 	// 110, 100,  32,  71, 101, 110, 116, 108,
		// 	// 101, 109, 101, 110,  32, 111, 102,  32,
		// 	// 116, 104, 101,  32,  99, 108,  97, 115,
		// 	// 115,  32, 111, 102
		// 	const text = 'Ladies and Gentlemen of the class of'
		// 	const plaintext = Uint8Array.from(
		// 		text.split('').map((char) => char.charCodeAt(0))
		// 	)

		// 	const privateInput: PrivateInput = {
		// 		key: Buffer.alloc(keySizeBytes, 2),
		// 	}

		// 	const iv = new Uint8Array(Array.from(Array(12).keys()))

		// 	const ciphertext = encryptData(
		// 		algorithm,
		// 		plaintext,
		// 		privateInput.key,
		// 		iv
		// 	)
		// 	const publicInput: PublicInput = { ciphertext, iv: iv }

		// 	const proof = await generateProof({
		// 		algorithm,
		// 		privateInput,
		// 		publicInput,
		// 		operator,
		// 	})
		// 	// client will send proof to witness
		// 	// witness would verify proof
		// 	await verifyProof({ proof, publicInput, operator })
		// })

		// it('should verify encrypted data with another counter', async() => {
		// 	const totalPlaintext = new Uint8Array(randomBytes(chunkSizeBytes * 5))
		// 	// use two blocks as offset (not chunks)
		// 	const offsetBytes = 2 * getBlockSizeBytes(algorithm)

		// 	const iv = Buffer.alloc(12, 3)
		// 	const privateInput: PrivateInput = {
		// 		key: Buffer.alloc(keySizeBytes, 2),
		// 	}

		// 	const totalCiphertext = encryptData(
		// 		algorithm,
		// 		totalPlaintext,
		// 		privateInput.key,
		// 		iv
		// 	)
		// 	const ciphertext = totalCiphertext.subarray(
		// 		offsetBytes,
		// 		chunkSizeBytes + offsetBytes
		// 	)

		// 	const publicInput = { ciphertext, iv, offsetBytes }
		// 	const proof = await generateProof({
		// 		algorithm,
		// 		privateInput,
		// 		publicInput,
		// 		operator,
		// 	})

		// 	await verifyProof({ proof, publicInput, operator })
		// })

		// it('should fail to verify incorrect data', async() => {
		// 	const plaintext = Buffer.alloc(encLength, 1)

		// 	const privateInput: PrivateInput = {
		// 		key: Buffer.alloc(keySizeBytes, 2),
		// 	}

		// 	const iv = Buffer.alloc(12, 3)
		// 	const ciphertext = encryptData(
		// 		algorithm,
		// 		plaintext,
		// 		privateInput.key,
		// 		iv
		// 	)
		// 	const publicInput: PublicInput = { ciphertext, iv }

		// 	const proof = await generateProof({
		// 		algorithm,
		// 		privateInput,
		// 		publicInput,
		// 		operator,
		// 	})
		// 	if(zkEngine === 'barretenberg') {
		// 		(proof.proofData as Uint8Array)[0] =
		//       ((proof.proofData as Uint8Array)[0] + 1) % 256
		// 	} else {
		// 		for(let i = 0; i < proof.plaintext.length; i++) {
		// 			proof.plaintext[i] = 0
		// 		}
		// 	}

		// 	await expect(
		// 		verifyProof({ proof, publicInput, operator })
		// 	).rejects.toHaveProperty('message', 'invalid proof')
		// })
	})
})
