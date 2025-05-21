import * as fs from 'fs'

export function encodeBlob(blob: object): string {
  return Buffer.from(JSON.stringify(blob)).toString('base64')
}

export function readTxt(path: string): string[] {
  return fs.readFileSync(path, 'utf8').split('\n')
}

export function readJson(path: string): object {
  return JSON.parse(fs.readFileSync(path, 'utf8'))
}