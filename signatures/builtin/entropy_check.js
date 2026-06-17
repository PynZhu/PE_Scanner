/**
 * @file entropy_check.js
 * @brief Entropy analysis signature script
 * @date 2026-06-17
 *
 * Performs detailed entropy analysis on PE file sections.
 * Detects packed, encrypted, or obfuscated code based on
 * entropy values and section characteristics.
 *
 * Usage:
 *   This script is loaded by CScriptManager and executed automatically.
 *   It defines a run() function that returns analysis results.
 */

(function() {
    'use strict';

    /**
     * Entropy thresholds for different risk levels
     */
    var THRESHOLDS = {
        HIGH: 7.0,      // Very high entropy - likely packed/encrypted
        MEDIUM: 6.5,    // Elevated entropy - possibly packed
        LOW: 6.0,       // Slightly elevated entropy
        NORMAL: 4.5     // Normal code entropy
    };

    /**
     * Expected entropy ranges for standard section types
     */
    var EXPECTED_ENTROPY = {
        '.text':  { min: 4.5, max: 6.5, desc: 'Code section' },
        '.data':  { min: 1.0, max: 4.0, desc: 'Data section' },
        '.rdata': { min: 1.0, max: 5.0, desc: 'Read-only data' },
        '.rsrc':  { min: 2.0, max: 7.5, desc: 'Resource section' },
        '.reloc': { min: 0.5, max: 3.0, desc: 'Relocation section' },
        '.bss':   { min: 0.0, max: 0.1, desc: 'Uninitialized data' },
        '.idata': { min: 1.0, max: 4.0, desc: 'Import data' },
        '.edata': { min: 1.0, max: 4.0, desc: 'Export data' },
        '.pdata': { min: 1.0, max: 3.0, desc: 'Exception data' },
        '.tls':   { min: 1.0, max: 5.0, desc: 'Thread local storage' }
    };

    /**
     * Calculate Shannon entropy for a byte array
     * @param {Uint8Array} data - Byte data to analyze
     * @return {number} Entropy value (0.0 - 8.0)
     */
    function calculateEntropy(data) {
        if (!data || data.length === 0) return 0.0;

        var freq = {};
        var len = data.length;

        // Count byte frequencies
        for (var i = 0; i < len; i++) {
            var byte = data[i];
            if (freq[byte] === undefined) {
                freq[byte] = 0;
            }
            freq[byte]++;
        }

        // Calculate Shannon entropy
        var entropy = 0.0;
        for (var b in freq) {
            if (freq.hasOwnProperty(b)) {
                var p = freq[b] / len;
                if (p > 0) {
                    entropy -= p * (Math.log(p) / Math.LN2);
                }
            }
        }

        return entropy;
    }

    /**
     * Check if a section's entropy is anomalous for its type
     * @param {Object} section - Section object from pe.getSection()
     * @param {number} entropy - Calculated entropy value
     * @return {Object|null} Anomaly description or null
     */
    function checkSectionAnomaly(section, entropy) {
        var expected = EXPECTED_ENTROPY[section.name];
        if (!expected) return null;

        if (entropy > expected.max) {
            return {
                type: 'high',
                message: section.name + ' entropy (' + entropy.toFixed(2) +
                    ') exceeds expected maximum (' + expected.max + ') for ' +
                    expected.desc
            };
        }

        if (entropy < expected.min && entropy > 0.1) {
            return {
                type: 'low',
                message: section.name + ' entropy (' + entropy.toFixed(2) +
                    ') is below expected minimum (' + expected.min + ') for ' +
                    expected.desc
            };
        }

        return null;
    }

    /**
     * Analyze byte patterns for suspicious content
     * @param {Uint8Array} data - Section data
     * @return {Object} Pattern analysis results
     */
    function analyzePatterns(data) {
        var result = {
            nullRatio: 0,
            printableRatio: 0,
            repeatingRatio: 0,
            suspicious: false
        };

        if (!data || data.length < 16) return result;

        var nullCount = 0;
        var printableCount = 0;
        var repeatingCount = 0;
        var len = data.length;

        for (var i = 0; i < len; i++) {
            if (data[i] === 0) nullCount++;
            if (data[i] >= 32 && data[i] <= 126) printableCount++;
        }

        // Check for repeating byte patterns (common in packed code)
        var step = Math.max(1, Math.floor(len / 100));
        for (var j = 0; j < len - step; j += step) {
            if (data[j] === data[j + step]) {
                repeatingCount++;
            }
        }

        result.nullRatio = nullCount / len;
        result.printableRatio = printableCount / len;
        result.repeatingRatio = repeatingCount / (len / step);

        // Suspicious if very high null ratio or very low printable ratio
        if (result.nullRatio > 0.8) result.suspicious = true;
        if (result.printableRatio < 0.1 && len > 100) result.suspicious = true;

        return result;
    }

    /**
     * Main analysis function
     * @return {Object} Analysis result with description, riskLevel, and details
     */
    function run() {
        var result = {
            description: 'Entropy Analysis',
            riskLevel: 'none',
            details: []
        };

        var sectionCount = pe.getSectionCount();
        if (sectionCount === 0) {
            result.details.push('No sections found in PE file');
            return result;
        }

        var maxEntropy = 0;
        var maxEntropySection = '';
        var anomalies = [];
        var suspiciousPatterns = 0;
        var totalEntropy = 0;

        for (var i = 0; i < sectionCount; i++) {
            var section = pe.getSection(i);
            if (!section) continue;

            // Use the pre-calculated entropy from the parser
            var entropy = section.entropy;
            totalEntropy += entropy;

            if (entropy > maxEntropy) {
                maxEntropy = entropy;
                maxEntropySection = section.name;
            }

            // Check for anomalies
            var anomaly = checkSectionAnomaly(section, entropy);
            if (anomaly) {
                anomalies.push(anomaly);
                result.details.push(anomaly.message);
            }

            // Read raw section data for pattern analysis
            // (only for sections with reasonable size)
            if (section.rawSize > 0 && section.rawSize <= 1024 * 1024) {
                try {
                    var rawData = pe.readBytes(section.virtualAddress, Math.min(section.rawSize, 4096));
                    if (rawData && rawData.byteLength > 0) {
                        var patterns = analyzePatterns(rawData);
                        if (patterns.suspicious) {
                            suspiciousPatterns++;
                            result.details.push('Suspicious byte pattern in ' +
                                section.name + ' (nulls: ' +
                                (patterns.nullRatio * 100).toFixed(1) +
                                '%, printable: ' +
                                (patterns.printableRatio * 100).toFixed(1) + '%)');
                        }
                    }
                } catch (e) {
                    // Skip sections that can't be read
                }
            }
        }

        // Calculate average entropy
        var avgEntropy = totalEntropy / sectionCount;

        // Determine risk level based on entropy analysis
        if (maxEntropy > THRESHOLDS.HIGH) {
            result.riskLevel = 'high';
            result.description = 'Very high entropy detected - file is likely packed or encrypted';
        } else if (maxEntropy > THRESHOLDS.MEDIUM && anomalies.length > 0) {
            result.riskLevel = 'medium';
            result.description = 'Elevated entropy with anomalies detected';
        } else if (maxEntropy > THRESHOLDS.MEDIUM) {
            result.riskLevel = 'medium';
            result.description = 'Elevated entropy detected in one or more sections';
        } else if (anomalies.length > 0 || suspiciousPatterns > 0) {
            result.riskLevel = 'low';
            result.description = 'Minor entropy anomalies detected';
        } else {
            result.description = 'Entropy values within normal range';
        }

        // Add summary
        result.details.unshift('Summary: max entropy = ' + maxEntropy.toFixed(2) +
            ' (' + maxEntropySection + '), avg entropy = ' +
            avgEntropy.toFixed(2) + ', anomalies = ' +
            anomalies.length + ', suspicious patterns = ' +
            suspiciousPatterns);

        return result;
    }

    // Export the run function
    return run;
})();
