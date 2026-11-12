package com.rasp.probe;

public final class AgentArtifactManifest {
    private final String version;
    private final String protocolVersion;
    private final String downloadUrl;
    private final String sha256;
    private final String signature;
    private final String status;
    private final int rolloutPercent;

    public AgentArtifactManifest(String version, String protocolVersion, String downloadUrl, String sha256, String signature, String status, int rolloutPercent) {
        this.version = version;
        this.protocolVersion = protocolVersion;
        this.downloadUrl = downloadUrl;
        this.sha256 = sha256;
        this.signature = signature;
        this.status = status;
        this.rolloutPercent = rolloutPercent;
    }

    public String version() {
        return version;
    }

    public String protocolVersion() {
        return protocolVersion;
    }

    public String downloadUrl() {
        return downloadUrl;
    }

    public String sha256() {
        return sha256;
    }

    public String signature() {
        return signature;
    }

    public String status() {
        return status;
    }

    public int rolloutPercent() {
        return rolloutPercent;
    }


    public boolean validFor(ProbeConfig config) {
        return version != null && !version.isBlank()
                && protocolVersion != null && protocolVersion.equals(config.protocolVersion())
                && downloadUrl != null && !downloadUrl.isBlank()
                && sha256 != null && !sha256.isBlank();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AgentArtifactManifest)) {
            return false;
        }
        AgentArtifactManifest that = (AgentArtifactManifest) o;
        return java.util.Objects.equals(version, that.version)
            && java.util.Objects.equals(protocolVersion, that.protocolVersion)
            && java.util.Objects.equals(downloadUrl, that.downloadUrl)
            && java.util.Objects.equals(sha256, that.sha256)
            && java.util.Objects.equals(signature, that.signature)
            && java.util.Objects.equals(status, that.status)
            && java.util.Objects.equals(rolloutPercent, that.rolloutPercent);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(version, protocolVersion, downloadUrl, sha256, signature, status, rolloutPercent);
    }

    @Override
    public String toString() {
        return "AgentArtifactManifest[" + "version=" + version + ", " + "protocolVersion=" + protocolVersion + ", " + "downloadUrl=" + downloadUrl + ", " + "sha256=" + sha256 + ", " + "signature=" + signature + ", " + "status=" + status + ", " + "rolloutPercent=" + rolloutPercent + "]";
    }
}
