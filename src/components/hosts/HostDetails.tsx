"use client";

import Link from "next/link";
import { useMemo } from "react";
import styled, { type DefaultTheme } from "styled-components";

import type { DatasetSource } from "@/server/datasetStore";
import type { NormalizedHost } from "@/server/normalize";

import { HostSummaryPanel } from "./HostSummaryPanel";

type HostDetailsProps = {
  host: NormalizedHost;
  datasetId?: string;
  datasetLabel?: string;
  datasetSource?: DatasetSource;
  datasetNotice?: string;
};

type SeverityBadgeProps = {
  $level: NormalizedHost["riskBadge"]["level"];
};

type CertificateInfo = {
  fingerprint: string;
  issuer?: string;
  subject?: string;
  selfSigned?: boolean;
};

type MalwareSignal = {
  servicePort: number;
  name: string;
  type?: string;
  confidence?: number;
  threatActors?: string[];
};

export function HostDetails({
  host,
  datasetId,
  datasetLabel,
  datasetSource,
  datasetNotice,
}: HostDetailsProps) {
  const certificateSummaries = useMemo(() => collectCertificates(host), [host]);
  const malwareSignals = useMemo(() => collectMalwareSignals(host), [host]);
  const listHref = datasetId
    ? `/hosts?dataset=${encodeURIComponent(datasetId)}`
    : "/hosts";
  const sourceLabel = describeDatasetSource(datasetSource ?? "sample");
  const datasetLabelText = datasetLabel ?? "Bundled sample dataset";

  return (
    <PageWrapper>
      <TopBar>
        <div>
          <BackLink href={listHref}>← Back to hosts</BackLink>
          <IPAddress>{host.ip}</IPAddress>
          <MetadataRow>
            <MetaItem>{host.geoSummary}</MetaItem>
            <Divider role="presentation" />
            <MetaItem>{host.asnSummary}</MetaItem>
            {host.host.operating_system && (
              <>
                <Divider role="presentation" />
                <MetaItem>
                  OS {formatOperatingSystem(host.host.operating_system)}
                </MetaItem>
              </>
            )}
            {host.host.dns?.hostname && (
              <>
                <Divider role="presentation" />
                <MetaItem>DNS {host.host.dns.hostname}</MetaItem>
              </>
            )}
          </MetadataRow>
          <DatasetContext aria-label="Dataset context">
            <DatasetBadge>{sourceLabel}</DatasetBadge>
            <DatasetLabel>{datasetLabelText}</DatasetLabel>
          </DatasetContext>
          {datasetNotice ? (
            <DatasetNotice role="status">
              <DatasetNoticeIcon aria-hidden="true">ℹ️</DatasetNoticeIcon>
              <span>{datasetNotice}</span>
            </DatasetNotice>
          ) : null}
        </div>
        <RiskBadge $level={host.riskBadge.level}>
          <span aria-hidden="true" />
          <span>{host.riskBadge.label}</span>
        </RiskBadge>
      </TopBar>

      <LeadStats>
        <StatCard>
          <StatLabel>Service count</StatLabel>
          <StatValue>{host.serviceCount}</StatValue>
          <StatHint>
            Across {Object.keys(host.serviceCountsByProtocol).length} protocols and {host.openPorts.length} open ports.
          </StatHint>
        </StatCard>
        <StatCard>
          <StatLabel>Vulnerability posture</StatLabel>
          <StatValue>{host.vulnerabilities.maxSeverity}</StatValue>
          <StatHint>
            {host.vulnerabilities.total} total findings, highest CVSS {host.vulnerabilities.highestCvss ?? "—"}.
          </StatHint>
        </StatCard>
        <StatCard>
          <StatLabel>TLS coverage</StatLabel>
          <StatValue>
            {host.tlsEnabledCount}/{host.serviceCount}
          </StatValue>
          <StatHint>
            {host.hasCertificates
              ? host.hasSelfSignedCertificate
                ? "Contains self-signed certificates."
                : "Certificates observed across TLS-enabled services."
              : "No certificates detected."}
          </StatHint>
        </StatCard>
      </LeadStats>

      <Layout>
        <PrimaryColumn>
          <Section>
            <SectionHeader>
              <SectionTitle>Services & banners</SectionTitle>
              <SectionHint>{host.representativeBanners.length} representative banners captured.</SectionHint>
            </SectionHeader>
            <ServicesList>
              {host.host.services.map((service) => (
                <ServiceCard key={`${service.port}/${service.protocol}`}>
                  <ServiceHeader>
                    <ServiceTitle>
                      {service.protocol.toUpperCase()} • Port {service.port}
                    </ServiceTitle>
                    {service.authentication_required && <Tag $tone="warning">Auth required</Tag>}
                    {service.access_restricted && <Tag $tone="info">Restricted</Tag>}
                  </ServiceHeader>

                  {service.banner && <ServiceBanner>{service.banner}</ServiceBanner>}

                  <ServiceMeta>
                    <MetaBlock>
                      <MetaLabel>Software</MetaLabel>
                      {service.software?.length ? (
                        <MetaValue>
                          {service.software
                            .map((software) =>
                              [software.vendor, software.product, software.version]
                                .filter(Boolean)
                                .join(" "),
                            )
                            .join("; ")}
                        </MetaValue>
                      ) : (
                        <Placeholder>No fingerprinted software</Placeholder>) }
                    </MetaBlock>

                    <MetaBlock>
                      <MetaLabel>Vulnerabilities</MetaLabel>
                      {service.vulnerabilities?.length ? (
                        <VulnList>
                          {service.vulnerabilities.map((vuln) => (
                            <li key={vuln.cve_id}>
                              <strong>{vuln.cve_id}</strong> · {vuln.severity}
                              {typeof vuln.cvss_score === "number" && ` (${vuln.cvss_score.toFixed(1)})`}
                              {vuln.description && <small> — {vuln.description}</small>}
                            </li>
                          ))}
                        </VulnList>
                      ) : (
                        <Placeholder>No CVEs linked to this service</Placeholder>)}
                    </MetaBlock>

                    <MetaBlock>
                      <MetaLabel>TLS & certificates</MetaLabel>
                      {service.tls_enabled ? (
                        service.certificate ? (
                          <CertificateSummary>
                            <div>
                              <strong>{service.certificate.subject ?? "Unknown subject"}</strong>
                              <CertificateMeta>
                                Fingerprint {service.certificate.fingerprint_sha256.slice(0, 18)}…
                              </CertificateMeta>
                              {service.certificate.issuer && (
                                <CertificateMeta>Issuer {service.certificate.issuer}</CertificateMeta>
                              )}
                            </div>
                            {service.certificate.self_signed && <Tag $tone="warning">Self-signed</Tag>}
                          </CertificateSummary>
                        ) : (
                          <Placeholder>TLS enabled, certificate details missing</Placeholder>
                        )
                      ) : (
                        <Placeholder>No TLS reported</Placeholder>
                      )}
                    </MetaBlock>

                    {service.malware_detected && (
                      <MetaBlock>
                        <MetaLabel>Malware</MetaLabel>
                        <MetaValue>
                          <strong>{service.malware_detected.name}</strong>
                          {service.malware_detected.type && ` · ${service.malware_detected.type}`}
                          {typeof service.malware_detected.confidence === "number" && ` (${(service.malware_detected.confidence * 100).toFixed(0)}% confidence)`}
                          {service.malware_detected.threat_actors?.length ? (
                            <small>
                              Actors: {service.malware_detected.threat_actors.join(", ")}
                            </small>
                          ) : null}
                        </MetaValue>
                      </MetaBlock>
                    )}
                  </ServiceMeta>
                </ServiceCard>
              ))}
            </ServicesList>
          </Section>

          <Section>
            <SectionHeader>
              <SectionTitle>Aggregated vulnerabilities</SectionTitle>
              <SectionHint>
                {host.vulnerabilities.total} total across {host.vulnerabilities.uniqueCveCount} unique CVEs.
              </SectionHint>
            </SectionHeader>
            {host.vulnerabilities.top.length === 0 ? (
              <Placeholder>No vulnerability records available.</Placeholder>
            ) : (
              <VulnTable>
                <thead>
                  <tr>
                    <th scope="col">CVE</th>
                    <th scope="col">Severity</th>
                    <th scope="col">CVSS</th>
                    <th scope="col">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {host.vulnerabilities.top.map((vuln) => (
                    <tr key={vuln.cveId}>
                      <td>{vuln.cveId}</td>
                      <td>{vuln.severity}</td>
                      <td>{vuln.cvssScore ? vuln.cvssScore.toFixed(1) : "—"}</td>
                      <td>{vuln.description ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </VulnTable>
            )}
          </Section>
        </PrimaryColumn>

        <SecondaryColumn>
          <HostSummaryPanel host={host} datasetId={datasetId} />

          <Section>
            <SectionHeader>
              <SectionTitle>Threat intelligence</SectionTitle>
              <SectionHint>Signals from dataset annotations and service-level detections.</SectionHint>
            </SectionHeader>
            <ThreatGrid>
              <ThreatBox>
                <ThreatHeading>Risk level</ThreatHeading>
                <ThreatValue>{host.threat.riskLevel ?? "Unclassified"}</ThreatValue>
                {host.threat.rawRiskLevel && (
                  <ThreatHint>Raw label: {host.threat.rawRiskLevel}</ThreatHint>
                )}
              </ThreatBox>

              <ThreatBox>
                <ThreatHeading>Security labels</ThreatHeading>
                <TagList>
                  {host.threat.securityLabels.length === 0 ? (
                    <Placeholder>No labels present</Placeholder>
                  ) : (
                    host.threat.securityLabels.map((label) => <Tag key={label}>{label}</Tag>)
                  )}
                </TagList>
              </ThreatBox>

              <ThreatBox>
                <ThreatHeading>Malware families</ThreatHeading>
                <TagList>
                  {host.threat.malwareFamilies.length === 0 ? (
                    <Placeholder>No families listed</Placeholder>
                  ) : (
                    host.threat.malwareFamilies.map((family) => <Tag key={family}>{family}</Tag>)
                  )}
                </TagList>
              </ThreatBox>
            </ThreatGrid>

            {malwareSignals.length > 0 && (
              <ThreatBox>
                <ThreatHeading>Service-level malware detections</ThreatHeading>
                <DetectionList>
                  {malwareSignals.map((signal) => (
                    <li key={`${signal.servicePort}-${signal.name}`}>
                      <strong>{signal.name}</strong> on port {signal.servicePort}
                      {signal.type && ` (${signal.type})`}
                      {typeof signal.confidence === "number" && ` • ${(signal.confidence * 100).toFixed(0)}% confidence`}
                      {signal.threatActors?.length && (
                        <small> Actors: {signal.threatActors.join(", ")}</small>
                      )}
                    </li>
                  ))}
                </DetectionList>
              </ThreatBox>
            )}
          </Section>

          <Section>
            <SectionHeader>
              <SectionTitle>Representative banners</SectionTitle>
            </SectionHeader>
            {host.representativeBanners.length === 0 ? (
              <Placeholder>No banners captured.</Placeholder>
            ) : (
              <BannerList>
                {host.representativeBanners.map((banner) => (
                  <BannerItem key={banner}>{banner}</BannerItem>
                ))}
              </BannerList>
            )}
          </Section>

          <Section>
            <SectionHeader>
              <SectionTitle>Certificates</SectionTitle>
              <SectionHint>{certificateSummaries.length} unique certificates observed.</SectionHint>
            </SectionHeader>
            {certificateSummaries.length === 0 ? (
              <Placeholder>No certificate metadata recorded.</Placeholder>
            ) : (
              <CertificateGrid>
                {certificateSummaries.map((cert) => (
                  <CertificateCard key={cert.fingerprint}>
                    <strong>{cert.subject ?? "Unknown subject"}</strong>
                    {cert.issuer && <small>Issuer: {cert.issuer}</small>}
                    <small>Fingerprint {cert.fingerprint.slice(0, 24)}…</small>
                    {cert.selfSigned && <Tag $tone="warning">Self-signed</Tag>}
                  </CertificateCard>
                ))}
              </CertificateGrid>
            )}
          </Section>
        </SecondaryColumn>
      </Layout>
    </PageWrapper>
  );
}

function formatOperatingSystem(os: NormalizedHost["host"]["operating_system"]): string {
  if (!os) {
    return "Unknown";
  }
  return [os.vendor, os.product, os.version].filter(Boolean).join(" ");
}

function collectCertificates(host: NormalizedHost): CertificateInfo[] {
  const seen = new Map<string, CertificateInfo>();
  for (const service of host.host.services) {
    if (service.certificate?.fingerprint_sha256) {
      const fingerprint = service.certificate.fingerprint_sha256;
      if (!seen.has(fingerprint)) {
        seen.set(fingerprint, {
          fingerprint,
          issuer: service.certificate.issuer,
          subject: service.certificate.subject,
          selfSigned: service.certificate.self_signed,
        });
      }
    }
  }
  return Array.from(seen.values());
}

function collectMalwareSignals(host: NormalizedHost): MalwareSignal[] {
  const signals: MalwareSignal[] = [];
  for (const service of host.host.services) {
    if (service.malware_detected) {
      signals.push({
        servicePort: service.port,
        name: service.malware_detected.name,
        type: service.malware_detected.type ?? undefined,
        confidence: service.malware_detected.confidence ?? undefined,
        threatActors: service.malware_detected.threat_actors ?? undefined,
      });
    }
  }
  return signals;
}

function describeDatasetSource(source: DatasetSource): string {
  switch (source) {
    case "upload":
      return "Uploaded dataset";
    case "api":
      return "API dataset";
    case "sample":
      return "Sample dataset";
    default:
      return "Dataset";
  }
}

function severityColor(level: SeverityBadgeProps["$level"], theme: DefaultTheme) {
  switch (level) {
    case "critical":
      return theme.colors.danger;
    case "high":
      return theme.colors.warning;
    case "medium":
      return theme.colors.accent;
    case "low":
      return theme.colors.success;
    case "informational":
      return theme.colors.accentContrast;
    default:
      return theme.colors.textMuted;
  }
}

const PageWrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing(6)};
  width: min(100%, 76rem);
  margin: 0 auto;
  padding-bottom: ${({ theme }) => theme.spacing(8)};
`;

const TopBar = styled.header`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: ${({ theme }) => theme.spacing(4)};
  flex-wrap: wrap;
  padding: ${({ theme }) => theme.spacing(5)};
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.lg};
  box-shadow: ${({ theme }) => theme.shadow.sm};
`;

const BackLink = styled(Link)`
  display: inline-flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2)};
  font-size: 0.9rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.primary};
  text-decoration: none;
  margin-bottom: ${({ theme }) => theme.spacing(1)};
  transition: color 0.2s ease, transform 0.2s ease;

  &:hover,
  &:focus-visible {
    color: ${({ theme }) => theme.colors.primaryDark};
    transform: translateX(-2px);
  }
`;

const IPAddress = styled.h1`
  margin: 0;
  font-size: clamp(2.1rem, 4vw, 2.75rem);
  color: ${({ theme }) => theme.colors.textPrimary};
  letter-spacing: -0.01em;
`;

const MetadataRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2)};
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-top: ${({ theme }) => theme.spacing(2)};
`;

const MetaItem = styled.span`
  font-size: 0.95rem;
`;

const DatasetContext = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2.5)};
  margin-top: ${({ theme }) => theme.spacing(3)};
  flex-wrap: wrap;
`;

const DatasetBadge = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: ${({ theme }) => theme.spacing(1.5)}
    ${({ theme }) => theme.spacing(2.5)};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.border};
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: ${({ theme }) => theme.colors.textMuted};
`;

const DatasetLabel = styled.span`
  font-size: 0.95rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const DatasetNotice = styled.p`
  display: inline-flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2)};
  margin: ${({ theme }) => theme.spacing(3)} 0 0;
  font-size: 0.95rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const DatasetNoticeIcon = styled.span`
  font-size: 1rem;
  line-height: 1;
`;

const Divider = styled.span`
  width: 0.25rem;
  height: 0.25rem;
  border-radius: 999px;
  background: ${({ theme }) => theme.colors.border};
`;

const RiskBadge = styled.div<SeverityBadgeProps>`
  display: inline-flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2)};
  padding: ${({ theme }) => theme.spacing(2.5)} ${({ theme }) => theme.spacing(3.5)};
  border-radius: ${({ theme }) => theme.radius.lg};
  border: 1px solid ${({ theme, $level }) => severityColor($level, theme)};
  color: ${({ theme, $level }) => severityColor($level, theme)};
  background: ${({ theme, $level }) => `color-mix(in srgb, ${severityColor($level, theme)} 18%, transparent)`};
  font-weight: 600;

  span[aria-hidden="true"] {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 999px;
    background: currentColor;
  }
`;

const LeadStats = styled.section`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: ${({ theme }) => theme.spacing(3)};
  padding: ${({ theme }) => theme.spacing(3)};
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.lg};
  box-shadow: ${({ theme }) => theme.shadow.sm};
`;

const StatCard = styled.article`
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: ${({ theme }) => theme.spacing(3.5)};
  box-shadow: none;
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
`;

const StatLabel = styled.span`
  font-size: 0.85rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.textMuted};
  text-transform: uppercase;
  letter-spacing: 0.04em;
`;

const StatValue = styled.span`
  font-size: 1.8rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const StatHint = styled.span`
  color: ${({ theme }) => theme.colors.textSecondary};
  font-size: 0.95rem;
`;

const Layout = styled.div`
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  gap: ${({ theme }) => theme.spacing(5)};

  @media (max-width: 1100px) {
    grid-template-columns: 1fr;
  }
`;

const PrimaryColumn = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(4)};
`;

const SecondaryColumn = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(4)};
`;

const Section = styled.section`
  display: grid;
  gap: ${({ theme }) => theme.spacing(3)};
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.lg};
  padding: ${({ theme }) => theme.spacing(4)};
  box-shadow: ${({ theme }) => theme.shadow.sm};
`;

const SectionHeader = styled.header`
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: ${({ theme }) => theme.spacing(2)};
  justify-content: space-between;
`;

const SectionTitle = styled.h2`
  margin: 0;
  font-size: 1.45rem;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const SectionHint = styled.span`
  font-size: 0.95rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const ServicesList = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(3)};
`;

const ServiceCard = styled.article`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2)};
  padding: ${({ theme }) => theme.spacing(3)};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.surface};
  box-shadow: ${({ theme }) => theme.shadow.sm};
`;

const ServiceHeader = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: ${({ theme }) => theme.spacing(2)};
  align-items: center;
  justify-content: space-between;
`;

const ServiceTitle = styled.h3`
  margin: 0;
  font-size: 1.2rem;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const ServiceBanner = styled.p`
  margin: 0;
  padding: ${({ theme }) => theme.spacing(2)};
  border-radius: ${({ theme }) => theme.radius.sm};
  background: ${({ theme }) => theme.colors.surfaceMuted};
  color: ${({ theme }) => theme.colors.textSecondary};
  font-family: "Consolas", "SFMono-Regular", monospace;
  font-size: 0.9rem;
`;

const ServiceMeta = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2.5)};
`;
const MetaBlock = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(1)};
`;

const MetaLabel = styled.span`
  font-size: 0.85rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.textMuted};
  letter-spacing: 0.06em;
  text-transform: uppercase;
`;

const MetaValue = styled.span`
  color: ${({ theme }) => theme.colors.textSecondary};
  line-height: 1.5;
`;

const Placeholder = styled.span`
  color: ${({ theme }) => theme.colors.textMuted};
`;

const VulnList = styled.ul`
  margin: 0;
  padding-left: ${({ theme }) => theme.spacing(4)};
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const CertificateSummary = styled.div`
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: ${({ theme }) => theme.spacing(2)};
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const CertificateMeta = styled.small`
  display: block;
  color: ${({ theme }) => theme.colors.textMuted};
`;

const VulnTable = styled.table`
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
  border-radius: ${({ theme }) => theme.radius.md};

  th,
  td {
    text-align: left;
    padding: ${({ theme }) => theme.spacing(2)};
    border-bottom: 1px solid ${({ theme }) => theme.colors.border};
  }

  th {
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: ${({ theme }) => theme.colors.textMuted};
    background: ${({ theme }) => theme.colors.surfaceMuted};
  }

  tr:last-of-type td {
    border-bottom: none;
  }
`;

const ThreatGrid = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(3)};
`;

const ThreatBox = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
  padding: ${({ theme }) => theme.spacing(3)};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.surfaceMuted};
`;

const ThreatHeading = styled.h3`
  margin: 0;
  font-size: 1rem;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const ThreatValue = styled.span`
  font-size: 1.1rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const ThreatHint = styled.small`
  color: ${({ theme }) => theme.colors.textMuted};
`;

const TagList = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: ${({ theme }) => theme.spacing(1)};
`;

const Tag = styled.span<{ $tone?: "warning" | "info" | "default" }>`
  display: inline-flex;
  align-items: center;
  padding: ${({ theme }) => theme.spacing(1.5)} ${({ theme }) => theme.spacing(2.5)};
  border-radius: ${({ theme }) => theme.radius.sm};
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;

  ${({ theme, $tone = "default" }) => {
    switch ($tone) {
      case "warning":
        return `background: rgba(245, 158, 11, 0.18); color: ${theme.colors.warning};`;
      case "info":
        return `background: rgba(44, 79, 94, 0.16); color: ${theme.colors.primary};`;
      default:
        return `background: ${theme.colors.surfaceMuted}; color: ${theme.colors.textSecondary};`;
    }
  }}
`;

const DetectionList = styled.ul`
  margin: 0;
  padding-left: ${({ theme }) => theme.spacing(4)};
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const BannerList = styled.ul`
  margin: 0;
  padding-left: ${({ theme }) => theme.spacing(3.5)};
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const BannerItem = styled.li`
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: ${({ theme }) => theme.spacing(2)};
  font-family: "Consolas", "SFMono-Regular", monospace;
  font-size: 0.9rem;
`;

const CertificateGrid = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2.5)};
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
`;

const CertificateCard = styled.div`
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: ${({ theme }) => theme.spacing(2.5)};
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.25)};
  background: ${({ theme }) => theme.colors.surface};
  box-shadow: ${({ theme }) => theme.shadow.sm};
  color: ${({ theme }) => theme.colors.textSecondary};
`;
