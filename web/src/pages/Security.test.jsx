import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import Security from './Security'

describe('Security page', () => {
  it('renders runtime-backed protection states instead of hard-coded active badges', async () => {
    const ws = {
      connected: true,
      events: [
        { method: 'Browser.injectionAttemptDetected', params: { url: 'https://example.com/?token=secret-token', blocked: true }, ts: Date.now() },
      ],
      call: vi.fn(async (method) => {
        if (method === 'security.status') {
          return {
            browserActive: false,
            securityEnabled: true,
            signaturePatternCount: 13,
            sandboxBlockedAPIs: ['fetch', 'WebSocket'],
            scanner: {
              lastScan: {
                status: 'warning',
                riskScore: 0.4,
                matchCount: 1,
                url: 'https://example.com/?token=%5Bredacted%5D',
                matches: [{ pattern: 'role_hijack', content: 'token=[redacted]', severity: 2 }],
              },
            },
            protections: [
              { key: 'ax_filter', name: 'Injection-Proof AX Filter', description: 'desc', status: 'disabled', details: 'No browser session.' },
              { key: 'signatures', name: 'Injection Signature Scanner', description: 'desc', status: 'available', details: '13 signatures loaded.' },
            ],
          }
        }
        return {}
      }),
    }

    render(<Security ws={ws} />)

    expect(await screen.findByText('Protection Status')).toBeInTheDocument()
    expect(screen.getByText('suite: enabled')).toBeInTheDocument()
    expect(screen.getByText('disabled')).toBeInTheDocument()
    expect(screen.getByText('available')).toBeInTheDocument()
    expect(screen.getByText('Browser active: No')).toBeInTheDocument()
    expect(screen.getByText('Signature patterns loaded: 13')).toBeInTheDocument()
    expect(screen.getByText('Scanner')).toBeInTheDocument()
    expect(screen.getByText('warning')).toBeInTheDocument()
    expect(screen.getByText(/INJECTION/)).toBeInTheDocument()
    expect(screen.queryByText(/secret-token/)).not.toBeInTheDocument()
    expect(screen.getAllByText(/token=\[redacted\]/).length).toBeGreaterThan(0)
  })

  it('runs scanner and exposes a guarded kill switch action', async () => {
    const ws = {
      connected: true,
      events: [],
      call: vi.fn(async (method) => {
        if (method === 'security.status') {
          return { scanner: {}, protections: [], sandboxBlockedAPIs: [], signaturePatternCount: 13 }
        }
        if (method === 'security.scan') {
          return {
            status: 'critical',
            clean: false,
            riskScore: 0.8,
            matchCount: 1,
            url: 'https://example.com/?token=%5Bredacted%5D',
            matches: [{ pattern: 'ignore_previous_instructions', content: 'ignore previous instructions', severity: 3 }],
          }
        }
        if (method === 'security.killSwitch') {
          return { activated: true, killedAgents: 0, browserStopped: true, reason: 'manual panel kill switch' }
        }
        return {}
      }),
    }

    render(<Security ws={ws} />)

    fireEvent.click(await screen.findByText('Run Scan'))
    await waitFor(() => expect(ws.call).toHaveBeenCalledWith('security.scan', { killOnRisk: true, threshold: 0.7 }))
    expect(await screen.findByText('critical')).toBeInTheDocument()
    expect(screen.getByText(/ignore_previous_instructions/)).toBeInTheDocument()

    fireEvent.click(screen.getByText('Kill Switch'))
    expect(await screen.findByText('Confirm kill switch')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Activate'))
    await waitFor(() => expect(ws.call).toHaveBeenCalledWith('security.killSwitch', { reason: 'manual panel kill switch' }))
    expect(await screen.findByText(/browser stopped/)).toBeInTheDocument()
  })
})
