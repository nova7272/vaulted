import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { QrCode } from "../components/QrCode";

interface UserInfo {
  walletAddress: string;
  publicKey: string;
  hasPreKeys: boolean;
  expiresAt: string;
  hasVaultedWallet?: boolean;
  vaultedIdentityId?: string | null;
}
interface Props {
  user: UserInfo | null;
}
interface OracleStatus {
  authenticated: boolean;
  walletAddress: string | null;
  expiresAt: string | null;
  hasRefreshToken: boolean;
  role: string | null;
  deviceFingerprint: string;
  needsRefresh: boolean;
}

interface DevicePairingRequest {
  pairingRequestId: string;
  challenge: string;
  oracleUrl: string;
  expiresAt: string;
  deviceName?: string | null;
  devicePublicKey: string;
  qrPayload: unknown;
}
interface DevicePairingStatus {
  status: string;
  identityId?: string | null;
  deviceId?: string | null;
  pairedAt?: string | null;
  paired: boolean;
}
interface XrplSigningRequest {
  signingRequestId: string;
  challenge: string;
  oracleUrl: string;
  expiresAt: string;
  txJsonHash: string;
  qrPayload: unknown;
}
interface XrplSigningStatus {
  status: string;
  identityId?: string | null;
  txJsonHash?: string | null;
  expectedXrplAccount?: string | null;
  approvedByDeviceId?: string | null;
  approvalSignature?: string | null;
  approvedAt?: string | null;
  approved: boolean;
}
interface VaultedDevice {
  deviceId: string;
  identityId: string;
  devicePublicKey: string;
  devicePublicKeyFingerprint: string;
  deviceName?: string | null;
  status: string;
  createdAt: string;
  revokedAt?: string | null;
  isCurrentDevice: boolean;
}

export default function SettingsScreen({ user }: Props) {
  const [balance, setBalance] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [oracleStatus, setOracleStatus] = useState<OracleStatus | null>(null);
  const [devices, setDevices] = useState<VaultedDevice[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [devicesError, setDevicesError] = useState<string | null>(null);

  const [pairingRequest, setPairingRequest] = useState<DevicePairingRequest | null>(null);
  const [pairingStatus, setPairingStatus] = useState<DevicePairingStatus | null>(null);
  const [pairingLoading, setPairingLoading] = useState(false);
  const [pairingError, setPairingError] = useState<string | null>(null);

  const [xrplTxJson, setXrplTxJson] = useState('');
  const [xrplExpectedAccount, setXrplExpectedAccount] = useState('');
  const [xrplHumanSummary, setXrplHumanSummary] = useState('');
  const [xrplSigningRequest, setXrplSigningRequest] = useState<XrplSigningRequest | null>(null);
  const [xrplSigningStatus, setXrplSigningStatus] = useState<XrplSigningStatus | null>(null);
  const [xrplSigningLoading, setXrplSigningLoading] = useState(false);
  const [xrplSigningError, setXrplSigningError] = useState<string | null>(null);

  useEffect(() => {
    fetchOracle();
    fetchDevices();
  }, []);

  useEffect(() => {
    if (!pairingRequest) return;
    if (pairingStatus?.status === "approved" || pairingStatus?.status === "expired") return;

    let cancelled = false;
    const poll = async () => {
      try {
        const status = await invoke<DevicePairingStatus>("poll_vaulted_device_pairing", {
          pairingRequestId: pairingRequest.pairingRequestId,
        });
        if (cancelled) return;
        setPairingStatus(status);
        if (status.status === "approved") {
          await fetchDevices();
        }
      } catch (e) {
        if (!cancelled) setPairingError(String(e));
      }
    };

    void poll();
    const id = window.setInterval(poll, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [pairingRequest, pairingStatus?.status]);

  useEffect(() => {
    if (!xrplSigningRequest) return;
    if (xrplSigningStatus?.status === "approved" || xrplSigningStatus?.status === "expired") return;

    let cancelled = false;
    const poll = async () => {
      try {
        const status = await invoke<XrplSigningStatus>("poll_vaulted_xrpl_signing_request", {
          signingRequestId: xrplSigningRequest.signingRequestId,
        });
        if (cancelled) return;
        setXrplSigningStatus(status);
      } catch (e) {
        if (!cancelled) setXrplSigningError(String(e));
      }
    };

    void poll();
    const id = window.setInterval(poll, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [xrplSigningRequest, xrplSigningStatus?.status]);

  const fetchBalance = async () => {
    try {
      setLoading(true);
      setBalance(await invoke<string>("get_xrp_balance"));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const fetchOracle = async () => {
    try {
      setOracleStatus(
        await invoke<OracleStatus>("get_oracle_auth_status_extended"),
      );
    } catch (e) {
      console.error(e);
    }
  };

  const fetchDevices = async () => {
    try {
      setDevicesLoading(true);
      setDevicesError(null);
      setDevices(
        await invoke<VaultedDevice[]>("list_vaulted_identity_devices", {
          includeRevoked: true,
        }),
      );
    } catch (e) {
      console.error(e);
      setDevicesError(String(e));
    } finally {
      setDevicesLoading(false);
    }
  };

  const startDevicePairing = async () => {
    try {
      setPairingLoading(true);
      setPairingError(null);
      setPairingStatus(null);
      const request = await invoke<DevicePairingRequest>("start_vaulted_device_pairing", {});
      setPairingRequest(request);
    } catch (e) {
      console.error(e);
      setPairingError(String(e));
    } finally {
      setPairingLoading(false);
    }
  };

  const resetDevicePairing = () => {
    setPairingRequest(null);
    setPairingStatus(null);
    setPairingError(null);
  };

  const startXrplSigning = async () => {
    try {
      setXrplSigningLoading(true);
      setXrplSigningError(null);
      setXrplSigningStatus(null);

      let parsedTx: unknown;
      try {
        parsedTx = JSON.parse(xrplTxJson);
      } catch {
        throw new Error("XRPL transaction JSON is not valid JSON");
      }

      const request = await invoke<XrplSigningRequest>("start_vaulted_xrpl_signing_request", {
        xrplTxJson: parsedTx,
        expectedXrplAccount: xrplExpectedAccount.trim() || null,
        humanSummary: xrplHumanSummary.trim() || null,
      });
      setXrplSigningRequest(request);
    } catch (e) {
      console.error(e);
      setXrplSigningError(String(e));
    } finally {
      setXrplSigningLoading(false);
    }
  };

  const resetXrplSigning = () => {
    setXrplSigningRequest(null);
    setXrplSigningStatus(null);
    setXrplSigningError(null);
  };

  const fillSampleXrplTx = () => {
    const account = user?.walletAddress || "rEXAMPLE_ACCOUNT";
    setXrplExpectedAccount(account);
    setXrplHumanSummary("Review and approve this XRPL Payment transaction");
    setXrplTxJson(JSON.stringify({
      TransactionType: "Payment",
      Account: account,
      Destination: "rEXAMPLE_DESTINATION",
      Amount: "1000000",
    }, null, 2));
  };

  const revokeDevice = async (device: VaultedDevice) => {
    if (device.isCurrentDevice) {
      const ok = window.confirm(
        "This is the current device. Revoking it may block future device approval flows until you restore or pair another trusted device. Revoke it anyway?",
      );
      if (!ok) return;
    }
    try {
      await invoke<VaultedDevice>("revoke_vaulted_identity_device", {
        deviceId: device.deviceId,
      });
      await fetchDevices();
    } catch (e) {
      console.error(e);
      setDevicesError(String(e));
    }
  };

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const pairingQrValue = pairingRequest
    ? JSON.stringify(pairingRequest.qrPayload)
    : "";

  const xrplSigningQrValue = xrplSigningRequest
    ? JSON.stringify(xrplSigningRequest.qrPayload)
    : "";

  const xrplSigningExpired = xrplSigningRequest
    ? new Date(xrplSigningRequest.expiresAt).getTime() <= Date.now()
    : false;

  const xrplSigningStatusLabel = xrplSigningStatus?.status
    ? xrplSigningStatus.status.toUpperCase()
    : xrplSigningRequest
      ? xrplSigningExpired
        ? "EXPIRED"
        : "PENDING"
      : "NOT STARTED";

  const pairingExpired = pairingRequest
    ? new Date(pairingRequest.expiresAt).getTime() <= Date.now()
    : false;

  const pairingStatusLabel = pairingStatus?.status
    ? pairingStatus.status.toUpperCase()
    : pairingRequest
      ? pairingExpired
        ? "EXPIRED"
        : "PENDING"
      : "NOT STARTED";

  const fmtExpiry = (iso: string | null) => {
    if (!iso) return "N/A";
    const d = new Date(iso);
    const now = new Date();
    const diff = d.getTime() - now.getTime();
    if (diff < 0) return "Expired";
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m remaining`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m remaining`;
  };

  const fmtDate = (iso?: string | null) =>
    iso ? new Date(iso).toLocaleString() : "—";

  const Section = ({
    title,
    children,
  }: {
    title: string;
    children: React.ReactNode;
  }) => (
    <div
      style={{
        background: "var(--bg-2)",
        borderRadius: "var(--radius-md)",
        padding: "20px 22px",
        marginBottom: 14,
        border: "1px solid var(--line)",
      }}
    >
      <p
        style={{
          fontWeight: 600,
          color: "var(--fg-0)",
          fontSize: 14,
          margin: "0 0 16px",
          paddingBottom: 12,
          borderBottom: "1px solid var(--line)",
        }}
      >
        {title}
      </p>
      {children}
    </div>
  );

  const Row = ({
    label,
    value,
    mono,
    onCopy,
  }: {
    label: string;
    value: string;
    mono?: boolean;
    onCopy?: () => void;
  }) => (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "8px 0",
      }}
    >
      <span style={{ color: "var(--fg-2)", fontSize: 13 }}>{label}</span>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span
          style={{
            color: "var(--fg-0)",
            fontSize: 13,
            fontWeight: 500,
            fontFamily: mono ? "var(--font-mono)" : "inherit",
            maxWidth: 260,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {value}
        </span>
        {onCopy && (
          <button
            onClick={onCopy}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: copied === label ? "#6ac79a" : "#868b98",
              padding: 2,
              fontSize: 12,
            }}
          >
            {copied === label ? "✓" : "⧉"}
          </button>
        )}
      </div>
    </div>
  );

  const Dot = ({ ok }: { ok: boolean }) => (
    <span
      style={{
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: ok ? "var(--ok)" : "var(--danger)",
        display: "inline-block",
        marginRight: 8,
        boxShadow: `0 0 0 3px ${ok ? "rgba(106,199,154,0.15)" : "rgba(224,122,106,0.15)"}`,
      }}
    />
  );

  return (
    <div className="fade-in" style={{ maxWidth: 620, margin: "0 auto" }}>
      <div className="v-section-head" style={{ marginBottom: 18 }}>
        <div>
          <div className="v-section-title">Settings</div>
          <div className="v-section-sub">
            Wallet, Oracle, and security details
          </div>
        </div>
      </div>

      <Section title="Wallet">
        <Row
          label="Address"
          value={user?.walletAddress || "Not connected"}
          mono
          onCopy={
            user?.walletAddress
              ? () => copy(user.walletAddress, "Address")
              : undefined
          }
        />
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: "#1f2430",
            borderRadius: 10,
            padding: "14px 18px",
            marginTop: 12,
          }}
        >
          <div>
            <p
              style={{
                fontSize: 11,
                color: "#868b98",
                textTransform: "uppercase",
                letterSpacing: ".05em",
                marginBottom: 4,
                fontWeight: 600,
              }}
            >
              XRP Balance
            </p>
            <p
              style={{
                fontSize: 24,
                fontWeight: 700,
                color: "#f2f3f7",
                margin: 0,
                fontFamily: "monospace",
              }}
            >
              {balance !== null ? (
                <>
                  {balance}{" "}
                  <span
                    style={{ fontSize: 14, color: "#868b98", fontWeight: 500 }}
                  >
                    XRP
                  </span>
                </>
              ) : (
                <span style={{ color: "#5a5f6c", fontSize: 18 }}>—</span>
              )}
            </p>
          </div>
          <button
            className="btn-secondary"
            style={{ padding: "8px 14px", fontSize: 13 }}
            onClick={fetchBalance}
            disabled={loading}
          >
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </Section>

      <Section title="Oracle Connection">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 14,
          }}
        >
          <Dot ok={oracleStatus?.authenticated ?? false} />
          <span
            style={{
              fontSize: 14,
              fontWeight: 500,
              color: oracleStatus?.authenticated ? "#6ac79a" : "#e07a6a",
            }}
          >
            {oracleStatus?.authenticated ? "Connected" : "Not connected"}
          </span>
          <button
            onClick={fetchOracle}
            style={{
              marginLeft: "auto",
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "#868b98",
              fontSize: 12,
            }}
          >
            Refresh
          </button>
        </div>
        <Row
          label="Token expiry"
          value={fmtExpiry(oracleStatus?.expiresAt ?? null)}
        />
        <Row
          label="Refresh token"
          value={oracleStatus?.hasRefreshToken ? "Available" : "None"}
        />
        <Row label="Role" value={oracleStatus?.role || "user"} />
        {oracleStatus?.needsRefresh && (
          <div
            style={{
              background: "rgba(251,191,36,0.1)",
              border: "1px solid rgba(251,191,36,0.3)",
              borderRadius: 8,
              padding: "8px 12px",
              marginTop: 10,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ color: "#e6b35a", fontSize: 12 }}>
              Token expires soon — will auto-refresh
            </span>
          </div>
        )}
      </Section>

      <Section title="Security">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 14,
          }}
        >
          <Dot ok={user?.hasPreKeys ?? false} />
          <span
            style={{
              fontSize: 14,
              fontWeight: 500,
              color: user?.hasPreKeys ? "#6ac79a" : "#e6b35a",
            }}
          >
            {user?.hasPreKeys
              ? "Vaulted seed-derived keys active"
              : "Vaulted keys not configured"}
          </span>
        </div>
        {user?.publicKey && (
          <Row
            label="Public encryption key"
            value={user.publicKey.slice(0, 32) + "..."}
            mono
            onCopy={() => copy(user.publicKey, "Public key")}
          />
        )}
        <Row
          label="Device fingerprint"
          value={
            oracleStatus?.deviceFingerprint
              ? oracleStatus.deviceFingerprint.slice(0, 16) + "..."
              : "Loading..."
          }
          mono
          onCopy={
            oracleStatus?.deviceFingerprint
              ? () => copy(oracleStatus.deviceFingerprint, "Device fingerprint")
              : undefined
          }
        />
      </Section>

      <Section title="Devices">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 12,
          }}
        >
          <span style={{ color: "var(--fg-2)", fontSize: 13 }}>
            Registered devices for this Vaulted identity.
          </span>
          <button
            onClick={fetchDevices}
            disabled={devicesLoading}
            style={{
              marginLeft: "auto",
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "#868b98",
              fontSize: 12,
            }}
          >
            {devicesLoading ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div
          style={{
            border: "1px solid var(--line)",
            borderRadius: 12,
            padding: "14px 16px",
            marginBottom: 12,
            background: "#1f2430",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  color: "var(--fg-0)",
                  fontSize: 13,
                  fontWeight: 700,
                  marginBottom: 4,
                }}
              >
                Pair this device
              </div>
              <div style={{ color: "var(--fg-2)", fontSize: 12, lineHeight: 1.5 }}>
                Generate a Scan-to-Pair QR code and approve it from an already trusted Vaulted device.
              </div>
            </div>
            <button
              onClick={pairingRequest ? resetDevicePairing : startDevicePairing}
              disabled={pairingLoading || !user?.vaultedIdentityId}
              className="btn-secondary"
              style={{ padding: "8px 12px", fontSize: 12, flexShrink: 0 }}
            >
              {pairingLoading
                ? "Starting…"
                : pairingRequest
                  ? "Close QR"
                  : "Pair new device"}
            </button>
          </div>

          {pairingError && (
            <div
              style={{
                background: "rgba(224,122,106,0.1)",
                border: "1px solid rgba(224,122,106,0.3)",
                borderRadius: 8,
                padding: "8px 12px",
                marginTop: 10,
                color: "#e07a6a",
                fontSize: 12,
              }}
            >
              {pairingError}
            </div>
          )}

          {pairingRequest && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "minmax(180px, 220px) 1fr",
                gap: 16,
                marginTop: 14,
                alignItems: "start",
              }}
            >
              <QrCode value={pairingQrValue} label="Pair device QR" size={210} />
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "4px 8px",
                    borderRadius: 999,
                    background:
                      pairingStatus?.status === "approved"
                        ? "rgba(106,199,154,0.12)"
                        : pairingStatusLabel === "EXPIRED"
                          ? "rgba(224,122,106,0.12)"
                          : "rgba(230,179,90,0.12)",
                    color:
                      pairingStatus?.status === "approved"
                        ? "#6ac79a"
                        : pairingStatusLabel === "EXPIRED"
                          ? "#e07a6a"
                          : "#e6b35a",
                    fontSize: 11,
                    fontWeight: 800,
                    letterSpacing: ".06em",
                    marginBottom: 10,
                  }}
                >
                  {pairingStatusLabel}
                </div>
                <Row
                  label="Expires"
                  value={fmtExpiry(pairingRequest.expiresAt)}
                />
                <Row
                  label="Device name"
                  value={pairingRequest.deviceName || "Vaulted desktop"}
                />
                <Row
                  label="Device public key"
                  value={pairingRequest.devicePublicKey.slice(0, 32) + "..."}
                  mono
                  onCopy={() => copy(pairingRequest.devicePublicKey, "Pairing device key")}
                />
                {pairingStatus?.deviceId && (
                  <Row
                    label="Paired device id"
                    value={pairingStatus.deviceId}
                    mono
                    onCopy={() => copy(pairingStatus.deviceId || "", "Pairing device id")}
                  />
                )}
                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button
                    className="btn-secondary"
                    style={{ padding: "7px 10px", fontSize: 12 }}
                    onClick={() => copy(pairingQrValue, "Pairing payload")}
                  >
                    {copied === "Pairing payload" ? "Copied" : "Copy payload"}
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ padding: "7px 10px", fontSize: 12 }}
                    onClick={async () => {
                      const status = await invoke<DevicePairingStatus>("poll_vaulted_device_pairing", {
                        pairingRequestId: pairingRequest.pairingRequestId,
                      });
                      setPairingStatus(status);
                      if (status.status === "approved") await fetchDevices();
                    }}
                  >
                    Check status
                  </button>
                </div>
                <div style={{ color: "var(--fg-2)", fontSize: 12, lineHeight: 1.5, marginTop: 10 }}>
                  Keep this screen open until the trusted device approves the request. The QR payload expires automatically and cannot be reused.
                </div>
              </div>
            </div>
          )}
        </div>
        {devicesError && (
          <div
            style={{
              background: "rgba(224,122,106,0.1)",
              border: "1px solid rgba(224,122,106,0.3)",
              borderRadius: 8,
              padding: "8px 12px",
              marginBottom: 10,
              color: "#e07a6a",
              fontSize: 12,
            }}
          >
            {devicesError}
          </div>
        )}
        {!user?.vaultedIdentityId && (
          <div style={{ color: "var(--fg-2)", fontSize: 13 }}>
            Unlock a Vaulted seed identity to view registered devices.
          </div>
        )}
        {user?.vaultedIdentityId && devices.length === 0 && !devicesLoading && (
          <div style={{ color: "var(--fg-2)", fontSize: 13 }}>
            No registered devices found yet.
          </div>
        )}
        <div style={{ display: "grid", gap: 10 }}>
          {devices.map((device) => {
            const active = device.status === "active" && !device.revokedAt;
            return (
              <div
                key={device.deviceId}
                style={{
                  border: "1px solid var(--line)",
                  borderRadius: 10,
                  padding: "12px 14px",
                  background: active ? "#1f2430" : "rgba(31,36,48,0.55)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 10,
                    alignItems: "flex-start",
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        marginBottom: 4,
                      }}
                    >
                      <span
                        style={{
                          color: "var(--fg-0)",
                          fontSize: 13,
                          fontWeight: 600,
                        }}
                      >
                        {device.deviceName || "Vaulted device"}
                      </span>
                      {device.isCurrentDevice && (
                        <span
                          style={{
                            color: "#6ac79a",
                            fontSize: 10,
                            fontWeight: 700,
                            letterSpacing: ".06em",
                          }}
                        >
                          CURRENT
                        </span>
                      )}
                      <span
                        style={{
                          color: active ? "#6ac79a" : "#e07a6a",
                          fontSize: 10,
                          fontWeight: 700,
                          letterSpacing: ".06em",
                        }}
                      >
                        {active ? "ACTIVE" : "REVOKED"}
                      </span>
                    </div>
                    <div
                      style={{
                        color: "var(--fg-2)",
                        fontSize: 12,
                        fontFamily: "var(--font-mono)",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        maxWidth: 360,
                      }}
                    >
                      {device.devicePublicKeyFingerprint}
                    </div>
                    <div
                      style={{
                        color: "var(--fg-2)",
                        fontSize: 11,
                        marginTop: 6,
                      }}
                    >
                      Added {fmtDate(device.createdAt)}
                      {device.revokedAt
                        ? ` · revoked ${fmtDate(device.revokedAt)}`
                        : ""}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() =>
                        copy(
                          device.devicePublicKeyFingerprint,
                          `Device ${device.deviceId}`,
                        )
                      }
                      className="btn-secondary"
                      style={{ padding: "6px 10px", fontSize: 12 }}
                    >
                      {copied === `Device ${device.deviceId}`
                        ? "Copied"
                        : "Copy"}
                    </button>
                    {active && (
                      <button
                        onClick={() => revokeDevice(device)}
                        className="btn-secondary"
                        style={{
                          padding: "6px 10px",
                          fontSize: 12,
                          color: "#e07a6a",
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <div
          style={{
            marginTop: 12,
            color: "var(--fg-2)",
            fontSize: 12,
            lineHeight: 1.5,
          }}
        >
          Revoking a device removes it from active approval flows. It does not
          delete files or revoke existing file grants; use Active shares for
          grant revocation.
        </div>
      </Section>

      <Section title="QR XRPL Signing">
        <div
          style={{
            border: "1px solid var(--line)",
            borderRadius: 12,
            padding: "14px 16px",
            background: "#1f2430",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
            <div>
              <div style={{ color: "var(--fg-0)", fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                Request approval for an XRPL transaction
              </div>
              <div style={{ color: "var(--fg-2)", fontSize: 12, lineHeight: 1.5 }}>
                Paste unsigned XRPL transaction JSON, show a QR code, and approve it from a trusted Vaulted device.
              </div>
            </div>
            <button
              onClick={xrplSigningRequest ? resetXrplSigning : fillSampleXrplTx}
              className="btn-secondary"
              style={{ padding: "8px 12px", fontSize: 12, flexShrink: 0 }}
            >
              {xrplSigningRequest ? "Close QR" : "Sample tx"}
            </button>
          </div>

          {xrplSigningError && (
            <div
              style={{
                background: "rgba(224,122,106,0.1)",
                border: "1px solid rgba(224,122,106,0.3)",
                borderRadius: 8,
                padding: "8px 12px",
                marginTop: 10,
                color: "#e07a6a",
                fontSize: 12,
              }}
            >
              {xrplSigningError}
            </div>
          )}

          {!xrplSigningRequest && (
            <div style={{ display: "grid", gap: 10, marginTop: 14 }}>
              <label style={{ color: "var(--fg-2)", fontSize: 12, fontWeight: 700 }}>
                Expected XRPL account
              </label>
              <input
                value={xrplExpectedAccount}
                onChange={(e) => setXrplExpectedAccount(e.target.value)}
                placeholder={user?.walletAddress || "Defaults to current Vaulted XRPL wallet"}
                style={{
                  background: "var(--bg-1)",
                  border: "1px solid var(--line)",
                  borderRadius: 10,
                  color: "var(--fg-0)",
                  padding: "10px 12px",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                }}
              />
              <label style={{ color: "var(--fg-2)", fontSize: 12, fontWeight: 700 }}>
                Human-readable summary
              </label>
              <input
                value={xrplHumanSummary}
                onChange={(e) => setXrplHumanSummary(e.target.value)}
                placeholder="Example: Mint Vaulted NFT for encrypted file"
                style={{
                  background: "var(--bg-1)",
                  border: "1px solid var(--line)",
                  borderRadius: 10,
                  color: "var(--fg-0)",
                  padding: "10px 12px",
                  fontSize: 12,
                }}
              />
              <label style={{ color: "var(--fg-2)", fontSize: 12, fontWeight: 700 }}>
                XRPL transaction JSON
              </label>
              <textarea
                value={xrplTxJson}
                onChange={(e) => setXrplTxJson(e.target.value)}
                placeholder={'{\n  "TransactionType": "Payment",\n  "Account": "r...",\n  "Destination": "r...",\n  "Amount": "1000000"\n}'}
                rows={9}
                style={{
                  background: "var(--bg-1)",
                  border: "1px solid var(--line)",
                  borderRadius: 10,
                  color: "var(--fg-0)",
                  padding: "10px 12px",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  resize: "vertical",
                }}
              />
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  onClick={startXrplSigning}
                  disabled={xrplSigningLoading || !xrplTxJson.trim() || !user?.vaultedIdentityId}
                  className="btn-secondary"
                  style={{ padding: "8px 12px", fontSize: 12 }}
                >
                  {xrplSigningLoading ? "Creating QR…" : "Create signing QR"}
                </button>
                <button
                  onClick={fillSampleXrplTx}
                  className="btn-secondary"
                  style={{ padding: "8px 12px", fontSize: 12 }}
                >
                  Fill sample
                </button>
              </div>
            </div>
          )}

          {xrplSigningRequest && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "minmax(180px, 220px) 1fr",
                gap: 16,
                marginTop: 14,
                alignItems: "start",
              }}
            >
              <QrCode value={xrplSigningQrValue} label="XRPL signing QR" size={210} />
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "4px 8px",
                    borderRadius: 999,
                    background:
                      xrplSigningStatus?.status === "approved"
                        ? "rgba(106,199,154,0.12)"
                        : xrplSigningStatusLabel === "EXPIRED"
                          ? "rgba(224,122,106,0.12)"
                          : "rgba(230,179,90,0.12)",
                    color:
                      xrplSigningStatus?.status === "approved"
                        ? "#6ac79a"
                        : xrplSigningStatusLabel === "EXPIRED"
                          ? "#e07a6a"
                          : "#e6b35a",
                    fontSize: 11,
                    fontWeight: 800,
                    letterSpacing: ".06em",
                    marginBottom: 10,
                  }}
                >
                  {xrplSigningStatusLabel}
                </div>
                <Row label="Expires" value={fmtExpiry(xrplSigningRequest.expiresAt)} />
                <Row label="Tx JSON hash" value={xrplSigningRequest.txJsonHash} mono onCopy={() => copy(xrplSigningRequest.txJsonHash, "XRPL tx hash")} />
                <Row label="Expected account" value={xrplSigningStatus?.expectedXrplAccount || xrplExpectedAccount || "Current Vaulted XRPL wallet"} mono />
                {xrplSigningStatus?.approvedByDeviceId && (
                  <Row label="Approved by" value={xrplSigningStatus.approvedByDeviceId} mono onCopy={() => copy(xrplSigningStatus.approvedByDeviceId || "", "XRPL approved device")} />
                )}
                {xrplSigningStatus?.approvedAt && (
                  <Row label="Approved at" value={fmtDate(xrplSigningStatus.approvedAt)} />
                )}
                {xrplSigningStatus?.approvalSignature && (
                  <Row label="Approval signature" value={xrplSigningStatus.approvalSignature.slice(0, 32) + "..."} mono onCopy={() => copy(xrplSigningStatus.approvalSignature || "", "XRPL approval signature")} />
                )}
                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button
                    className="btn-secondary"
                    style={{ padding: "7px 10px", fontSize: 12 }}
                    onClick={() => copy(xrplSigningQrValue, "XRPL signing payload")}
                  >
                    {copied === "XRPL signing payload" ? "Copied" : "Copy payload"}
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ padding: "7px 10px", fontSize: 12 }}
                    onClick={async () => {
                      const status = await invoke<XrplSigningStatus>("poll_vaulted_xrpl_signing_request", {
                        signingRequestId: xrplSigningRequest.signingRequestId,
                      });
                      setXrplSigningStatus(status);
                    }}
                  >
                    Check status
                  </button>
                </div>
                <div style={{ color: "var(--fg-2)", fontSize: 12, lineHeight: 1.5, marginTop: 10 }}>
                  This QR records a Vaulted identity approval for the transaction hash. It expires automatically and should be re-created if the transaction JSON changes.
                </div>
              </div>
            </div>
          )}
        </div>
      </Section>

      <Section title="About">
        <Row label="Version" value="XRPL Vault v0.1.0" />
        <Row label="Protocol" value="XRP Ledger (XRPL)" />
        <Row label="Encryption" value="Vaulted seed + KeyEnvelope" />
        <Row label="Access control" value="NFT ownership + grants" />
        <Row label="Cipher" value="AES-256-GCM" />
      </Section>
    </div>
  );
}
