import React, { useEffect, useState } from 'react'
import { redactSensitiveText } from '../utils/redact'

export default function Security({ ws }) {
  const [status, setStatus] = useState({ protections: [], sandboxBlockedAPIs: [], signaturePatternCount: 0, scanner: {} })
  const [scan, setScan] = useState(null)
  const [scanBusy, setScanBusy] = useState(false)
  const [killBusy, setKillBusy] = useState(false)
  const [autoKill, setAutoKill] = useState(true)
  const [threshold, setThreshold] = useState(0.7)
  const [confirmKill, setConfirmKill] = useState(false)
  const [notice, setNotice] = useState('')
  const injectionEvents = ws.events.filter(e => e.method === 'Browser.injectionAttemptDetected').slice(-20).reverse()

  const refreshStatus = () => {
    if (!ws.connected) return Promise.resolve()
    return ws.call('security.status')
      .then(result => {
        const next = result || {}
        setStatus(next)
        if (next.scanner?.lastScan) setScan(next.scanner.lastScan)
      })
      .catch(() => {})
  }

  useEffect(() => {
    refreshStatus()
  }, [ws.connected])

  const badgeClass = (protectionStatus) => {
    switch (protectionStatus) {
      case 'active':
      case 'clean':
        return 'badge-green'
      case 'available':
      case 'warning':
        return 'badge-blue'
      case 'critical':
        return 'badge-red'
      default:
        return 'badge-gray'
    }
  }

  const runScan = async () => {
    setScanBusy(true)
    setNotice('')
    try {
      const result = await ws.call('security.scan', { killOnRisk: autoKill, threshold: Number(threshold) || 0.7 })
      setScan(result)
      if (result?.killSwitch?.activated) {
        setNotice(`Kill switch activated: ${result.killSwitch.reason}`)
      } else {
        setNotice(result?.clean ? 'Scan clean' : `Scan found ${result?.matchCount || 0} matches`)
      }
      await refreshStatus()
    } catch (e) {
      setNotice(e.message || 'Scan failed')
    } finally {
      setScanBusy(false)
    }
  }

  const activateKillSwitch = async () => {
    setKillBusy(true)
    setNotice('')
    try {
      const result = await ws.call('security.killSwitch', { reason: 'manual panel kill switch' })
      setConfirmKill(false)
      setNotice(`Kill switch activated: ${result?.killedAgents || 0} agents stopped${result?.browserStopped ? ', browser stopped' : ''}`)
      await refreshStatus()
    } catch (e) {
      setNotice(e.message || 'Kill switch failed')
    } finally {
      setKillBusy(false)
    }
  }

  const lastKill = status.scanner?.killSwitch

  return (
    <div>
      <div className="page-header"><h1>Security</h1></div>

      {notice && (
        <div className={`panel-banner ${notice.includes('failed') ? 'panel-banner-red' : 'panel-banner-info'}`} style={{ marginBottom: 16 }}>
          <div>
            <strong>Security runtime</strong>
            <span>{notice}</span>
          </div>
        </div>
      )}

      {confirmKill && (
        <div className="panel-banner panel-banner-red" style={{ marginBottom: 16 }}>
          <div>
            <strong>Confirm kill switch</strong>
            <span>Stop all active agents and shut down the browser kernel.</span>
          </div>
          <div className="panel-banner-actions">
            <button className="btn btn-danger btn-sm" disabled={killBusy} onClick={activateKillSwitch}>{killBusy ? 'Stopping...' : 'Activate'}</button>
            <button className="btn btn-ghost btn-sm" disabled={killBusy} onClick={() => setConfirmKill(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Scanner</h3>
              <p className="card-subtitle">Current context signature sweep</p>
            </div>
            <span className={`badge ${badgeClass(scan?.status || 'idle')}`}>{scan?.status || 'idle'}</span>
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 16 }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#c8d0db', fontSize: 13 }}>
              <input type="checkbox" checked={autoKill} onChange={e => setAutoKill(e.target.checked)} />
              Auto kill
            </label>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#c8d0db', fontSize: 13 }}>
              Threshold
              <input className="input" style={{ width: 92 }} type="number" min="0.1" max="1" step="0.05" value={threshold} onChange={e => setThreshold(e.target.value)} />
            </label>
            <button className="btn btn-primary" disabled={!ws.connected || scanBusy} onClick={runScan}>{scanBusy ? 'Scanning...' : 'Run Scan'}</button>
            <button className="btn btn-danger" disabled={!ws.connected || killBusy} onClick={() => setConfirmKill(true)}>Kill Switch</button>
          </div>
          <div style={{ fontSize: 13, color: '#aaa', lineHeight: 1.8, marginBottom: 16 }}>
            <div>Risk score: {typeof scan?.riskScore === 'number' ? scan.riskScore.toFixed(2) : 'n/a'}</div>
            <div>Matches: {scan?.matchCount ?? 0}</div>
            <div>URL: {scan?.url || 'n/a'}</div>
            {lastKill?.activated && <div>Last kill: {lastKill.reason}</div>}
          </div>
          <div className="event-log" style={{ maxHeight: 260 }}>
            {(!scan?.matches || scan.matches.length === 0) && <p style={{ color: '#666' }}>No scanner matches.</p>}
            {(scan?.matches || []).map((match, i) => (
              <div key={`${match.pattern}-${i}`} className="event">
                <span className="event-time">S{match.severity} </span>
                <span style={{ color: match.severity >= 3 ? '#ef4444' : '#f7c561' }}>{match.pattern} </span>
                <span style={{ color: '#888', fontSize: 12 }}>{match.content}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="page-header" style={{ marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Protection Status</h3>
            <span className={`badge ${status.securityEnabled ? 'badge-green' : 'badge-gray'}`}>
              suite: {status.securityEnabled ? 'enabled' : 'disabled'}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(status.protections || []).map(protection => (
              <div key={protection.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #1e1e2e' }}>
                <div>
                  <div style={{ fontSize: 14, color: '#e0e0e8' }}>{protection.name}</div>
                  <div style={{ fontSize: 12, color: '#666' }}>{protection.description}</div>
                  {protection.details && <div style={{ fontSize: 11, color: '#777', marginTop: 4 }}>{protection.details}</div>}
                </div>
                <span className={`badge ${badgeClass(protection.status)}`}>{protection.status}</span>
              </div>
            ))}
            {(status.protections || []).length === 0 && <p style={{ color: '#666' }}>Security status unavailable.</p>}
          </div>
        </div>

        <div className="card">
          <h3>Runtime Summary</h3>
          <div style={{ fontSize: 13, color: '#aaa', lineHeight: 2, marginBottom: 24 }}>
            <div>Browser active: {status.browserActive ? 'Yes' : 'No'}</div>
            <div>Signature patterns loaded: {status.signaturePatternCount || 0}</div>
            <div>Sandbox blocked APIs: {(status.sandboxBlockedAPIs || []).join(', ') || 'none'}</div>
          </div>

          <h3>Injection Attempts ({injectionEvents.length})</h3>
          <div className="event-log" style={{ maxHeight: 400 }}>
            {injectionEvents.length === 0 && <p style={{ color: '#666' }}>No injection attempts detected.</p>}
            {injectionEvents.map((ev, i) => (
              <div key={i} className="event">
                <span className="event-time">{new Date(ev.ts).toLocaleTimeString()} </span>
                <span style={{ color: '#ef4444' }}>INJECTION </span>
                <span style={{ color: '#888', fontSize: 12 }}>{redactSensitiveText(ev.params).substring(0, 120)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
