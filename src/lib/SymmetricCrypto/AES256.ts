import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto'


const ALGORITHM_AES256: string = 'aes256'


export const encrypt = (key: string, cleartext: string): string => {
    const _salt = randomBytes(8).toString('hex')
    const _hash = scryptSync(key, _salt, 32)
    const _iv = randomBytes(8).toString('hex')
    const _cipher = createCipheriv(ALGORITHM_AES256, _hash, _iv)
    let encrypted = _cipher.update(cleartext, 'utf8', 'hex')
    encrypted += _cipher.final('hex')
    return `${_salt}:${_iv}:${encrypted}`
}

export const decrypt = (key: string, encryptedtext: string): string => {
    const [_salt, _iv, _encryptedtext] = encryptedtext.split(':')
    const _hash = scryptSync(key, _salt, 32)
    const _decipher = createDecipheriv(ALGORITHM_AES256, _hash, _iv)
    let decrypted = _decipher.update(_encryptedtext, 'hex', 'utf8')
    decrypted += _decipher.final('utf8')
    return decrypted
}
