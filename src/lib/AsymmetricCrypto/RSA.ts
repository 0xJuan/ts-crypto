import * as crypto from 'crypto'


const ALGORITHM_SIGNATURE = 'rsa-sha256'


export const generateKeyPairSync = () => {
    return crypto.generateKeyPairSync(
        'rsa'
        , {
            modulusLength: 4096
            , publicKeyEncoding: {
                type: 'spki'
                , format: 'pem'
            }
            , privateKeyEncoding: {
                type: 'pkcs8'
                , format: 'pem'
            }
        }
    )
}

export const publicEncrypt = (publicKey: string, cleartext: string): string => {
    const encrypted = crypto.publicEncrypt(
        publicKey
        , Buffer.from(cleartext)
    )
    return encrypted.toString('hex')
}

export const privateDecrypt = (privateKey: string, encryptedtext: string): string => {
    const decryptedData = crypto.privateDecrypt(
        privateKey
        , Buffer.from(encryptedtext, 'hex')
    )
    return decryptedData.toString('utf-8')
}

export const createSign = (privateKey: string, message: string): string => {
    const signer = crypto.createSign(ALGORITHM_SIGNATURE)
    signer.update(message)
    signer.end()
    return signer.sign(privateKey, 'hex')
}

export const createVerify = (publicKey: string, message: string, signature: string): boolean => {
    const verifier = crypto.createVerify(ALGORITHM_SIGNATURE)
    verifier.update(message)
    verifier.end()
    return verifier.verify(publicKey, signature, 'hex')
}
