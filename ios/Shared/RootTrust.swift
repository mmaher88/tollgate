import Foundation
import Security

/// Whether iOS trusts the Tollgate root for TLS, the way Safari will judge an intercepted
/// site: a throwaway leaf issued by the CA is evaluated with the SSL policy. A root
/// installed from a profile only passes once full trust is enabled in Settings, General,
/// About, Certificate Trust Settings.
enum RootTrust {
    static let checkHost = "trust-check.tollgate.invalid"

    /// Blocking: SecTrustEvaluateWithError may take a while, so call it off the main thread.
    static func isTrustedForTLS(coreDirectory: URL) -> Bool {
        guard let rootPEM = try? String(contentsOf: coreDirectory.appendingPathComponent("ca.pem"), encoding: .utf8),
              let leafDER = try? caTestLeaf(dataDir: coreDirectory.path, host: checkHost)
        else { return false }
        return isTrustedForTLS(leafDER: leafDER, rootPEM: rootPEM, host: checkHost)
    }

    static func isTrustedForTLS(leafDER: Data, rootPEM: String, host: String) -> Bool {
        let base64 = rootPEM
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard let rootDER = Data(base64Encoded: base64),
              let root = SecCertificateCreateWithData(nil, rootDER as CFData),
              let leaf = SecCertificateCreateWithData(nil, leafDER as CFData)
        else { return false }
        var trust: SecTrust?
        // The root is only a chain hint; anchors still come from the system and user trust store.
        guard SecTrustCreateWithCertificates([leaf, root] as CFArray,
                                             SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess,
              let trust
        else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}
