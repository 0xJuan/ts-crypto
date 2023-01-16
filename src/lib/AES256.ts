import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto'


export class AES256 {
    static algorithm: string = 'aes256'

    static encrypt = (key: string, cleartext: string): string => {
        const _salt = randomBytes(8).toString('hex')
        const _hash = scryptSync(key, _salt, 32)
        const _iv = randomBytes(8).toString('hex')
        const _cipher = createCipheriv(AES256.algorithm, _hash, _iv)
        let encrypted = _cipher.update(cleartext, 'utf8', 'hex')
        encrypted += _cipher.final('hex')
        return `${_salt}:${_iv}:${encrypted}`
    }

    static decrypt = (key: string, encryptedtext: string): string => {
        const [_salt, _iv, _encryptedtext] = encryptedtext.split(':')
        const _hash = scryptSync(key, _salt, 32)
        const _decipher = createDecipheriv(AES256.algorithm, _hash, _iv)
        let decrypted = _decipher.update(_encryptedtext, 'hex', 'utf8')
        decrypted += _decipher.final('utf8')
        return decrypted
    }
}
