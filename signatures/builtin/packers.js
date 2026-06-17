/**
 * @file packers.js
 * @brief Packer detection signature script
 * @date 2026-06-17
 *
 * Detects known packers and protectors by checking section names,
 * entropy values, and other PE characteristics.
 *
 * Usage:
 *   This script is loaded by CScriptManager and executed automatically.
 *   It defines a run() function that returns analysis results.
 */

(function() {
    'use strict';

    /**
     * Known packer section name patterns
     */
    var PACKER_SECTIONS = {
        'UPX0':     'UPX',
        'UPX1':     'UPX',
        'UPX2':     'UPX',
        '.UPX':     'UPX',
        'UPX!':     'UPX',
        '.packed':  'Generic Packer',
        '.pack':    'Generic Packer',
        'PACK':     'Generic Packer',
        '.themida': 'Themida',
        'themida':  'Themida',
        '.vmp0':    'VMProtect',
        '.vmp1':    'VMProtect',
        '.vmp2':    'VMProtect',
        '.vmp':     'VMProtect',
        '.aspack':  'ASPack',
        'ASPack':   'ASPack',
        '.petite':  'Petite',
        '.MPRESS':  'MPRESS',
        '.enigma':  'Enigma Protector',
        '.nsp0':    'NSPack',
        '.nsp1':    'NSPack',
        '.nsp2':    'NSPack',
        '.morph':   'Morphine',
        '.taz':     'Taz',
        '.svkp':    'SVKP',
        '.perplex': 'Perplex',
        '.sxdata':  'SXData',
        '.sxs':     'SXS',
        '.tls':     'TLS',
        '.00cfg':   'Control Flow Guard'
    };

    /**
     * Known standard section names (not suspicious)
     */
    var STANDARD_SECTIONS = [
        '.text', '.data', '.rdata', '.bss', '.idata', '.edata',
        '.rsrc', '.reloc', '.tls', '.CRT', '.pdata', '.xdata',
        '.debug', '.debug$S', '.debug$T', '.didata', '.sxdata',
        '.gfids', '.giats', '.rsrc$01', '.rsrc$02', '.didat',
        '.00cfg', '.msvcjmc', '.randata', '.ctors', '.dtors'
    ];

    /**
     * Main analysis function
     * @return {Object} Analysis result with description, riskLevel, and details
     */
    function run() {
        var result = {
            description: 'Packer/Protector Detection',
            riskLevel: 'none',
            details: []
        };

        var sectionCount = pe.getSectionCount();
        if (sectionCount === 0) {
            result.details.push('No sections found in PE file');
            return result;
        }

        var detectedPackers = {};
        var suspiciousCount = 0;
        var highEntropyCount = 0;
        var wxViolations = 0;

        for (var i = 0; i < sectionCount; i++) {
            var section = pe.getSection(i);
            if (!section) continue;

            // Check for known packer section names
            var packerName = PACKER_SECTIONS[section.name];
            if (packerName) {
                if (!detectedPackers[packerName]) {
                    detectedPackers[packerName] = [];
                }
                detectedPackers[packerName].push(section.name);
                result.details.push('Packer detected: ' + packerName +
                    ' (section: ' + section.name + ')');
            }

            // Check for high entropy (packed/encrypted code)
            if (section.entropy > 7.0) {
                highEntropyCount++;
                result.details.push('High entropy section: ' + section.name +
                    ' (entropy: ' + section.entropy.toFixed(2) + ')');
            } else if (section.entropy > 6.5) {
                result.details.push('Elevated entropy section: ' + section.name +
                    ' (entropy: ' + section.entropy.toFixed(2) + ')');
            }

            // Check for W^X violations (writable + executable)
            if (section.isWritable && section.isExecutable) {
                wxViolations++;
                result.details.push('W^X violation: ' + section.name +
                    ' is both writable and executable');
            }

            // Check for suspicious section names
            if (section.name.length > 0) {
                var isStandard = false;
                for (var j = 0; j < STANDARD_SECTIONS.length; j++) {
                    if (section.name === STANDARD_SECTIONS[j]) {
                        isStandard = true;
                        break;
                    }
                }
                if (!isStandard && !PACKER_SECTIONS[section.name]) {
                    suspiciousCount++;
                    result.details.push('Unusual section name: ' + section.name);
                }
            }
        }

        // Determine risk level
        var packerCount = 0;
        for (var p in detectedPackers) {
            if (detectedPackers.hasOwnProperty(p)) {
                packerCount += detectedPackers[p].length;
            }
        }

        if (packerCount > 0 && highEntropyCount > 0) {
            result.riskLevel = 'high';
            result.description = 'Packed file detected with high entropy sections';
        } else if (packerCount > 0) {
            result.riskLevel = 'medium';
            result.description = 'Known packer/protector detected';
        } else if (highEntropyCount > 1) {
            result.riskLevel = 'medium';
            result.description = 'Multiple high entropy sections detected';
        } else if (wxViolations > 0) {
            result.riskLevel = 'medium';
            result.description = 'W^X policy violations detected';
        } else if (highEntropyCount > 0 || suspiciousCount > 0) {
            result.riskLevel = 'low';
            result.description = 'Minor suspicious characteristics detected';
        } else {
            result.description = 'No packers or suspicious characteristics detected';
        }

        // Add summary
        if (packerCount > 0 || highEntropyCount > 0 || wxViolations > 0 || suspiciousCount > 0) {
            result.details.unshift('Summary: ' + packerCount + ' packer signatures, ' +
                highEntropyCount + ' high entropy sections, ' +
                wxViolations + ' W^X violations, ' +
                suspiciousCount + ' unusual section names');
        }

        return result;
    }

    // Export the run function
    return run;
})();
