/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderDetailRowModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderHeaderFactModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderImpactItemModel
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot

class BootloaderCardModelMapper {

    fun map(
        report: BootloaderReport,
    ): BootloaderCardModel {
        return BootloaderCardModel(
            title = "Bootloader",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildRows(report.stage, report.stateRows, statePlaceholders()),
            attestationRows = buildRows(
                report.stage,
                report.attestationRows,
                attestationPlaceholders()
            ),
            propertyRows = buildRows(report.stage, report.propertyRows, propertyPlaceholders()),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                consistencyPlaceholders()
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING -> "attestation + props de boot + consistencia de boot"
            BootloaderStage.FAILED -> "escaneo local de bootloader fallido"
            BootloaderStage.READY -> "${report.checkedPropertyCount} props · ${report.attestationChainLength} certs · ${report.consistencyFindingCount} cross-checks"
        }
    }

    private fun buildVerdict(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING -> "Escaneando estado de boot y evidencia de boot verificado"
            BootloaderStage.FAILED -> "Bootloader scan failed"
            BootloaderStage.READY -> when {
                report.dangerFindings.isNotEmpty() -> "${report.dangerFindings.size} critical boot integrity signal(s)"
                report.warningFindings.isNotEmpty() -> "${report.warningFindings.size} boot state signal(s) need review"
                report.state == BootloaderState.VERIFIED && report.evidenceMode == BootloaderEvidenceMode.ATTESTATION ->
                    "Bloqueado y attestation verificado"

                report.state == BootloaderState.VERIFIED -> "Bloqueado por propiedades de boot"
                report.state == BootloaderState.LOCKED_UNKNOWN -> "Estado bloqueado sin prueba completa"
                report.state == BootloaderState.UNKNOWN -> "Estado de boot inconcluso"
                else -> stateLabel(report.state)
            }
        }
    }

    private fun buildSummary(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING ->
                "Verificando RootOfTrust de attestation, confianza de certificados, propiedades de boot y consistencia de fuentes."

            BootloaderStage.FAILED ->
                report.errorMessage ?: "Bootloader scan failed before evidence could be assembled."

            BootloaderStage.READY -> when {
                report.dangerFindings.isNotEmpty() ->
                    "Estado desbloqueado, contradicciones de attestation, confianza de certificado rota o fallos de verified-boot indican confianza reducida en la cadena de boot."

                report.warningFindings.isNotEmpty() ->
                    "La cadena de boot no está obviamente rota, pero la evidencia aún muestra señales de root personalizado, solo software o coherencia que vale la pena revisar."

                report.evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY ->
                    "Las propiedades de boot parecen conservadoras, pero el resultado cae de vuelta a señales legibles por software porque el RootOfTrust de attestation no estuvo disponible."

                report.evidenceMode == BootloaderEvidenceMode.UNAVAILABLE ->
                    "Ni el RootOfTrust de attestation ni las propiedades de boot expusieron datos suficientes para un veredicto del bootloader."

                else ->
                    "Attestation and boot properties stayed aligned with a locked, verified boot chain."
            }
        }
    }

    private fun buildHeaderFacts(report: BootloaderReport): List<BootloaderHeaderFactModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> placeholderFacts(
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            BootloaderStage.READY -> listOf(
                BootloaderHeaderFactModel(
                    label = "Estado",
                    value = stateLabel(report.state),
                    status = report.toDetectorStatus(),
                ),
                BootloaderHeaderFactModel(
                    label = "Prueba",
                    value = proofLabel(report.evidenceMode),
                    status = when (report.evidenceMode) {
                        BootloaderEvidenceMode.ATTESTATION -> DetectorStatus.allClear()
                        BootloaderEvidenceMode.PROPERTIES_ONLY -> DetectorStatus.info(InfoKind.SUPPORT)
                        BootloaderEvidenceMode.UNAVAILABLE -> DetectorStatus.warning()
                    },
                ),
                BootloaderHeaderFactModel(
                    label = "Nivel",
                    value = tierLabel(report.tier),
                    status = when (report.tier) {
                        TeeTier.STRONGBOX,
                        TeeTier.TEE -> DetectorStatus.allClear()

                        TeeTier.SOFTWARE -> DetectorStatus.warning()
                        TeeTier.NONE,
                        TeeTier.UNKNOWN -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                BootloaderHeaderFactModel(
                    label = "Confianza",
                    value = trustLabel(report.trustRoot),
                    status = trustStatus(report),
                ),
            )
        }
    }

    private fun buildRows(
        stage: BootloaderStage,
        rows: List<BootloaderFinding>,
        placeholders: List<String>,
    ): List<BootloaderDetailRowModel> {
        return when (stage) {
            BootloaderStage.LOADING -> placeholderRows(
                placeholders,
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderRows(
                placeholders,
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            BootloaderStage.READY -> if (rows.isEmpty()) {
                listOf(
                    BootloaderDetailRowModel(
                        label = "Estado",
                        value = "Ninguno",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                        detail = "No se generaron filas para esta sección en este dispositivo.",
                    ),
                )
            } else {
                rows.map(::findingRow)
            }
        }
    }

    private fun buildImpactItems(report: BootloaderReport): List<BootloaderImpactItemModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> listOf(
                BootloaderImpactItemModel(
                    text = "Recolectando evidencia de attestation, verified-boot y consistencia de propiedades.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            BootloaderStage.FAILED -> listOf(
                BootloaderImpactItemModel(
                    text = report.errorMessage ?: "Escaneo de Bootloader fallido.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            BootloaderStage.READY -> report.impacts.map { impact ->
                BootloaderImpactItemModel(
                    text = impact.text,
                    status = severityStatus(impact.severity),
                )
            }
        }
    }

    private fun buildMethodRows(report: BootloaderReport): List<BootloaderDetailRowModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> placeholderRows(
                methodPlaceholders(),
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderRows(
                methodPlaceholders(),
                "Fallido",
                DetectorStatus.info(InfoKind.ERROR)
            )

            BootloaderStage.READY -> report.methods.map { result ->
                BootloaderDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: BootloaderReport): List<BootloaderDetailRowModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> placeholderRows(
                scanPlaceholders(),
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderRows(
                scanPlaceholders(),
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            BootloaderStage.READY -> listOf(
                BootloaderDetailRowModel(
                    label = "Propiedades verificadas",
                    value = report.checkedPropertyCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                BootloaderDetailRowModel(
                    label = "Propiedades observadas",
                    value = report.observedPropertyCount.toString(),
                    status = if (report.observedPropertyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                BootloaderDetailRowModel(
                    label = "Detecciones nativas",
                    value = report.nativePropertyHitCount.toString(),
                    status = if (report.nativePropertyHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                BootloaderDetailRowModel(
                    label = "Detecciones boot raw",
                    value = report.rawBootParamHitCount.toString(),
                    status = if (report.rawBootParamHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                BootloaderDetailRowModel(
                    label = "Discrepancias de fuente",
                    value = report.sourceMismatchCount.toString(),
                    status = if (report.sourceMismatchCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                BootloaderDetailRowModel(
                    label = "Cross-checks",
                    value = report.consistencyFindingCount.toString(),
                    status = if (report.consistencyFindingCount > 0) {
                        if (report.dangerFindings.any { it.group.name == "CONSISTENCY" }) DetectorStatus.danger() else DetectorStatus.warning()
                    } else {
                        DetectorStatus.allClear()
                    },
                ),
                BootloaderDetailRowModel(
                    label = "Cadena de attestation",
                    value = report.attestationChainLength.toString(),
                    status = when {
                        report.attestationChainLength == 0 -> DetectorStatus.danger()
                        report.attestationAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                BootloaderDetailRowModel(
                    label = "Respaldado por hardware",
                    value = if (report.hardwareBacked) "Sí" else "No",
                    status = if (report.hardwareBacked) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun findingRow(finding: BootloaderFinding): BootloaderDetailRowModel {
        return BootloaderDetailRowModel(
            label = finding.label,
            value = badgeValue(finding.value),
            status = severityStatus(finding.severity),
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus
    ): List<BootloaderHeaderFactModel> {
        return listOf(
            BootloaderHeaderFactModel("Estado", value, status),
            BootloaderHeaderFactModel("Prueba", value, status),
            BootloaderHeaderFactModel("Nivel", value, status),
            BootloaderHeaderFactModel("Confianza", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        value: String,
        status: DetectorStatus,
    ): List<BootloaderDetailRowModel> {
        return labels.map { label ->
            BootloaderDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun statePlaceholders(): List<String> =
        listOf("Boot state", "Evidence source", "Lock state", "Trust root")

    private fun attestationPlaceholders(): List<String> = listOf(
        "Attestation tier",
        "Certificate chain",
        "Attested boot state",
        "Attested deviceLocked"
    )

    private fun propertyPlaceholders(): List<String> = listOf(
        "ro.boot.flash.locked",
        "ro.boot.verifiedbootstate",
        "ro.boot.vbmeta.device_state",
        "partition.system.verified"
    )

    private fun consistencyPlaceholders(): List<String> = listOf(
        "Attested hash vs vbmeta digest",
        "Verified boot coherence",
        "Property source mismatch"
    )

    private fun methodPlaceholders(): List<String> = listOf(
        "Attestation de clave",
        "Confianza de certificado",
        "Consistencia de boot",
        "Catálogo de propiedades",
        "Reflection API",
        "getprop snapshot",
        "Native libc",
        "Parámetros de boot raw",
        "Consistencia de fuente",
        "Reglas de cruce",
    )

    private fun scanPlaceholders(): List<String> = listOf(
        "Propiedades verificadas",
        "Propiedades observadas",
        "Detecciones nativas",
        "Detecciones boot raw",
        "Discrepancias de fuente",
        "Cross-checks",
        "Cadena de attestation",
        "Respaldado por hardware",
    )

    private fun severityStatus(severity: BootloaderFindingSeverity): DetectorStatus {
        return when (severity) {
            BootloaderFindingSeverity.SAFE -> DetectorStatus.allClear()
            BootloaderFindingSeverity.WARNING -> DetectorStatus.warning()
            BootloaderFindingSeverity.DANGER -> DetectorStatus.danger()
            BootloaderFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: BootloaderMethodResult): DetectorStatus {
        return when (result.outcome) {
            BootloaderMethodOutcome.CLEAN -> DetectorStatus.allClear()
            BootloaderMethodOutcome.WARNING -> DetectorStatus.warning()
            BootloaderMethodOutcome.DANGER -> DetectorStatus.danger()
            BootloaderMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun proofLabel(mode: BootloaderEvidenceMode): String {
        return when (mode) {
            BootloaderEvidenceMode.ATTESTATION -> "Attestation"
            BootloaderEvidenceMode.PROPERTIES_ONLY -> "Props"
            BootloaderEvidenceMode.UNAVAILABLE -> "N/A"
        }
    }

    private fun stateLabel(state: BootloaderState): String {
        return when (state) {
            BootloaderState.VERIFIED -> "Verificado"
            BootloaderState.SELF_SIGNED -> "Personalizado"
            BootloaderState.UNLOCKED -> "Desbloqueado"
            BootloaderState.FAILED_VERIFICATION -> "Fallido"
            BootloaderState.LOCKED_UNKNOWN -> "¿Bloqueado?"
            BootloaderState.UNKNOWN -> "Desconocido"
        }
    }

    private fun tierLabel(tier: TeeTier): String {
        return when (tier) {
            TeeTier.STRONGBOX -> "StrongBox"
            TeeTier.TEE -> "TEE"
            TeeTier.SOFTWARE -> "Software"
            TeeTier.NONE -> "Ninguno"
            TeeTier.UNKNOWN -> "Desconocido"
        }
    }

    private fun trustLabel(trustRoot: TeeTrustRoot): String {
        return when (trustRoot) {
            TeeTrustRoot.GOOGLE -> "Google"
            TeeTrustRoot.GOOGLE_RKP -> "RKP"
            TeeTrustRoot.AOSP -> "AOSP"
            TeeTrustRoot.FACTORY -> "Fábrica"
            TeeTrustRoot.UNKNOWN -> "Desconocido"
        }
    }

    private fun trustStatus(report: BootloaderReport): DetectorStatus {
        return when {
            report.attestationChainLength == 0 -> DetectorStatus.danger()
            report.trustRoot == TeeTrustRoot.UNKNOWN -> DetectorStatus.danger()
            report.trustRoot == TeeTrustRoot.GOOGLE || report.trustRoot == TeeTrustRoot.GOOGLE_RKP ->
                DetectorStatus.allClear()

            report.trustRoot == TeeTrustRoot.AOSP -> DetectorStatus.warning()
            report.trustRoot == TeeTrustRoot.FACTORY -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun badgeValue(value: String): String {
        return if (value.length > 18) value.take(17) + "…" else value
    }

    private fun BootloaderReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            BootloaderStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            BootloaderStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            BootloaderStage.READY -> when {
                dangerFindings.isNotEmpty() -> DetectorStatus.danger()
                warningFindings.isNotEmpty() -> DetectorStatus.warning()
                evidenceMode == BootloaderEvidenceMode.UNAVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }
}
