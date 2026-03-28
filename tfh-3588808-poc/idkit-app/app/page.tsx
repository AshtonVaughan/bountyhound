'use client'

import { useState } from 'react'
import { IDKitWidget, VerificationLevel, ISuccessResult } from '@worldcoin/idkit'

const APP_ID = 'app_7c45d9d16bd9e044dfc09800fdfa68d8' as `app_${string}`
const ACTION = 'vote'

export default function Page() {
  const [proof, setProof] = useState<ISuccessResult | null>(null)
  const [status, setStatus] = useState('Ready — click Verify to open World ID widget')
  const [copied, setCopied] = useState(false)

  const handleVerify = async (result: ISuccessResult) => {
    // Don't forward to any server — just capture the proof
    console.log('PROOF CAPTURED:', JSON.stringify(result, null, 2))
    setProof(result)
    setStatus('Proof captured!')
    return Promise.resolve()
  }

  const onSuccess = (result: ISuccessResult) => {
    setProof(result)
    setStatus('SUCCESS')
  }

  const copy = () => {
    if (!proof) return
    navigator.clipboard.writeText(JSON.stringify(proof, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <h1 style={{ color: '#00ff88' }}>World ID Proof Capture</h1>
      <p>App: <code>{APP_ID}</code></p>
      <p>Action: <code>{ACTION}</code></p>
      <p style={{ color: '#888', fontSize: '0.85rem' }}>
        Open <a href="https://simulator.worldcoin.org" target="_blank" style={{ color: '#00ff88' }}>simulator.worldcoin.org</a> in
        another tab, select any identity, then click Verify below and paste/scan the code in the simulator.
      </p>

      <IDKitWidget
        app_id={APP_ID}
        action={ACTION}
        verification_level={VerificationLevel.Orb}
        handleVerify={handleVerify}
        onSuccess={onSuccess}
      >
        {({ open }) => (
          <button
            onClick={open}
            style={{
              background: '#00ff88', color: '#000', border: 'none',
              padding: '0.7rem 1.5rem', fontSize: '1rem', cursor: 'pointer',
              borderRadius: '4px', fontWeight: 'bold'
            }}
          >
            Verify with World ID
          </button>
        )}
      </IDKitWidget>

      <p style={{ color: status === 'SUCCESS' ? '#00ff88' : '#ffaa00', marginTop: '1rem' }}>
        {status}
      </p>

      {proof && (
        <div style={{ marginTop: '1.5rem' }}>
          <h2 style={{ color: '#00ff88' }}>Proof</h2>
          <pre style={{
            background: '#111', padding: '1rem', border: '1px solid #333',
            overflow: 'auto', maxHeight: '400px', whiteSpace: 'pre-wrap', wordBreak: 'break-all'
          }}>
            {JSON.stringify(proof, null, 2)}
          </pre>
          <button
            onClick={copy}
            style={{ background: '#333', color: '#fff', border: '1px solid #555', padding: '0.5rem 1rem', cursor: 'pointer', borderRadius: '4px', marginTop: '0.5rem' }}
          >
            {copied ? 'Copied!' : 'Copy JSON'}
          </button>

          <h3 style={{ color: '#888', marginTop: '1.5rem' }}>Individual fields</h3>
          {(['nullifier_hash', 'merkle_root', 'proof', 'verification_level'] as const).map(k => (
            <div key={k} style={{ marginBottom: '0.8rem' }}>
              <div style={{ color: '#888', fontSize: '0.8rem' }}>{k}</div>
              <pre style={{ background: '#111', padding: '0.5rem', border: '1px solid #222', wordBreak: 'break-all', whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>
                {(proof as any)[k]}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
