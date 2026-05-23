import { useState } from 'react';
import axios from 'axios';
import { API_ENDPOINTS, sortBySeverity } from '../utils/logicProtection';

const _ax = axios.create({ withCredentials: true });

export const useScanner = () => {
    const [findings, setFindings] = useState([]);
    const [loading,  setLoading]  = useState(false);
    const [error,    setError]    = useState(null);
    const [total,    setTotal]    = useState(0);
    const [recon,    setRecon]    = useState(null);
    const [riskInfo, setRiskInfo] = useState(null);

    const _handleResults = (data) => {
        // Bridge endpoints return { findings: [...] }
        // /start-scan returns { scan_result: { vulnerabilities: [...] } }
        const raw = (
            data.findings ||
            data.scan_result?.vulnerabilities ||
            data.vulnerabilities ||
            []
        );
        const sorted = sortBySeverity(raw);
        setFindings(sorted);
        setTotal(sorted.length);
        if (data.recon)      setRecon(data.recon);
        if (data.risk)       setRiskInfo({ level: data.risk, score: data.risk_score });
        if (data.risk_score) setRiskInfo(prev => ({ ...prev, score: data.risk_score }));
    };

    // Upload a ZIP file → SAST scanner (/analyze_code)
    const analyzeFile = async (file) => {
        if (!file) return;
        setLoading(true); setError(null);
        try {
            const form = new FormData();
            form.append('file', file);
            const { data } = await _ax.post(API_ENDPOINTS.ANALYZE_CODE, form);
            _handleResults(data);
            return data;
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    // Upload an Apache config text string → server config scanner (/fix_config)
    const analyzeConfig = async (configText) => {
        if (!configText?.trim()) return;
        setLoading(true); setError(null);
        try {
            const blob = new Blob([configText], { type: 'text/plain' });
            const form = new FormData();
            form.append('file', blob, 'config.conf');
            const { data } = await _ax.post(API_ENDPOINTS.FIX_CONFIG, form);
            _handleResults(data);
            return data;
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    // Upload an Apache config file → /fix_config
    const analyzeConfigFile = async (file) => {
        if (!file) return;
        setLoading(true); setError(null);
        try {
            const form = new FormData();
            form.append('file', file);
            const { data } = await _ax.post(API_ENDPOINTS.FIX_CONFIG, form);
            _handleResults(data);
            return data;
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    // Web URL scan → /scan_url
    const scanUrl = async (url) => {
        if (!url?.trim()) return;
        setLoading(true); setError(null);
        let clean = url.split('#')[0].trim();
        if (!clean.startsWith('http')) clean = 'http://' + clean;
        try {
            const { data } = await _ax.post(
                API_ENDPOINTS.SCAN_URL,
                { url: clean },
                { headers: { 'Content-Type': 'application/json' } }
            );
            _handleResults(data);
            return data;
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    // Network scan → /scan_network
    const scanNetwork = async (target, scanType = 'full') => {
        if (!target?.trim()) return;
        setLoading(true); setError(null);
        try {
            const { data } = await _ax.post(
                API_ENDPOINTS.SCAN_NETWORK,
                { target: target.trim(), scan_type: scanType },
                { headers: { 'Content-Type': 'application/json' } }
            );
            _handleResults(data);
            return data;
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    const reset = () => {
        setFindings([]); setError(null); setTotal(0); setRecon(null); setRiskInfo(null);
    };

    return {
        findings, loading, error, total, recon, riskInfo,
        analyzeFile, analyzeConfig, analyzeConfigFile,
        scanUrl, scanNetwork, reset,
    };
};
