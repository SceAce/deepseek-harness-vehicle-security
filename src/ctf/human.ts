import { createHash } from 'node:crypto'
import { emptyResult, type CtfHumanRequest, type CtfToolResultBase } from './types.js'

export interface HumanRequestResult extends CtfToolResultBase {
  requestId: string
  request: CtfHumanRequest
}

export function createHumanRequest(request: CtfHumanRequest): HumanRequestResult {
  const base = emptyResult('human_required')
  const requestId = `human-${createHash('sha256').update(JSON.stringify(request)).digest('hex').slice(0, 12)}`
  base.humanRequired.push(request)
  base.observations.push(`human action requested: ${request.title}`)
  return {
    ...base,
    requestId,
    request,
  }
}
