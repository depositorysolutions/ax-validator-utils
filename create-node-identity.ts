import { ValidatorClient } from './src/validator'

export async function main(): Promise<void> {
  try {
    // Create a new instance of the ValidatorClient
    const client = new ValidatorClient('validator')

    // Generate validator keys
    await client.createKeys()

    // Generate a token for the validator
    await client.createToken()
  } catch (error) {
    console.error('An error occurred:', error)
  }
}

main()
