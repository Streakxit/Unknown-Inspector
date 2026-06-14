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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxPolicyloadSeqnoProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentProbe
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxDetailRowModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxHeaderFactModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxImpactItemModel

class SelinuxCardModelMapper {

    fun map(report: SelinuxReport): SelinuxCardModel {
        return SelinuxCardModel(
            title = "SELinux",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildStateRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            policyRows = buildPolicyRows(report.policyAnalysis),
            policyNotes = buildPolicyNotes(report.policyAnalysis),
            auditRows = buildAuditRows(report.auditIntegrity),
            auditNotes = buildAuditNotes(report.auditIntegrity),
            deviceRows = buildDeviceRows(report),
            references = buildReferences(),
        )
    }

    private fun buildSubtitle(report: SelinuxReport): String {
        return when (report.stage) {
            SelinuxStage.LOADING -> "sysfs + getenforce + proc attr + app_zygote zygotePreload seqno + context oracle + policy + audit"
            SelinuxStage.FAILED -> "local status probe failed"
            SelinuxStage.READY -> buildString {
                append("7 local checks")
                if (report.policyAnalysis != null) {
                    append(" + policy")
                }
                if (report.auditIntegrity != null) {
                    append(" + audit integrity + side-channel")
                }
            }
        }
    }

    private fun buildVerdict(report: SelinuxReport): String {
        val contextValidity = contextValidityResult(report)
        val procAttrCurrent = procAttrCurrentResult(report)
        val policyloadSeqno = policyloadSeqnoResult(report)
        val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
        val repeatabilityFailed =
            contextValidity?.details?.contains("repeatability failed", ignoreCase = true) == true
        val appZygoteCarrierState = contextValiditySupportState(contextValidity)
        return when (report.stage) {
            SelinuxStage.LOADING -> "Escaneando estado de SELinux"
            SelinuxStage.FAILED -> "Escaneo de SELinux fallido"
            SelinuxStage.READY -> when (report.mode) {
                SelinuxMode.ENFORCING -> when {
                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> "Activo con reescritura de audit"
                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT ->
                        "Activo con contexto KSU materializado"
                    policyloadSeqno?.isSecure == false -> "Activo con split seqno app_zygote"
                    procAttrCurrent?.isSecure == false -> "Activo con anomalía attr-write app_zygote"
                    dirtyPolicyHit != null -> trustedPolicyRuleVerdict()
                    appZygoteCarrierState == AppZygoteCarrierSupportState.UNTRUSTED ->
                        "Activo con carrier app_zygote no confiable"
                    appZygoteCarrierState == AppZygoteCarrierSupportState.FAILED ->
                        "Activo con cobertura app_zygote reducida"

                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED ->
                        if (repeatabilityFailed) {
                            "Activo con oráculo de contexto inestable"
                        } else {
                            "Activo con oráculo de contexto no confiable"
                        }

                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS ->
                        "Activo con contexto dividido"

                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED -> "Activo con exposición de audit"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE -> "Activo con política débil"
                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> "Activo con riesgo de audit"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE -> "Activo con deriva de política"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.MINOR -> "Activo con deriva menor"
                    else -> "Activo"
                }

                SelinuxMode.PERMISSIVE -> "Permissive"
                SelinuxMode.DISABLED -> "Deshabilitado"
                SelinuxMode.UNKNOWN -> "Desconocido"
            }
        }
    }

    private fun buildSummary(report: SelinuxReport): String {
        val contextValidity = contextValidityResult(report)
        val procAttrCurrent = procAttrCurrentResult(report)
        val policyloadSeqno = policyloadSeqnoResult(report)
        val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
        val repeatabilityFailed =
            contextValidity?.details?.contains("repeatability failed", ignoreCase = true) == true
        val appZygoteCarrierState = contextValiditySupportState(contextValidity)
        return when (report.stage) {
            SelinuxStage.LOADING ->
                "Verificando sysfs, getenforce y /proc/self/attr/current para derivar el modo SELinux final."

            SelinuxStage.FAILED ->
                report.errorMessage
                    ?: "El escaneo de SELinux falló antes de recolectar evidencia local."

            SelinuxStage.READY -> when (report.mode) {
                SelinuxMode.ENFORCING -> {
                    val base = when (report.policyAnalysis?.weakness) {
                        SelinuxPolicyWeakness.SEVERE ->
                            "SELinux está activo, pero la política parece severamente debilitada o modificada."

                        SelinuxPolicyWeakness.MODERATE ->
                            "SELinux está activo, pero el análisis de política encontró deriva notable."

                        SelinuxPolicyWeakness.MINOR ->
                            "SELinux está activo y solo se detectó deriva menor de política."

                        SelinuxPolicyWeakness.NONE, null ->
                            "SELinux está activo y la política visible parece internamente consistente."
                    }
                    val extra = buildList {
                        if (report.paradoxDetected) {
                            add("Permission-denied probes also reinforced the enforcing verdict.")
                        }
                        if (procAttrCurrent?.isSecure == false) {
                            add(
                                "The dedicated app_zygote carrier hit anomalous /proc/self/attr/current write outcomes while probing privileged contexts: ${
                                    procAttrCurrent.status.removePrefix("Detected: ")
                                }.",
                            )
                        }
                        if (policyloadSeqno?.isSecure == false) {
                            add("The zygotePreload app_zygote carrier observed a policyload/access seqno split; treat this as KernelSU-specific evidence bounded to the preload carrier.")
                        }
                        if (dirtyPolicyHit != null) {
                            add(trustedPolicyRuleSummary(dirtyPolicyHit))
                        }
                        when (report.auditIntegrity?.state) {
                            SelinuxAuditIntegrityState.TAMPERED ->
                                add("Recent audit or log markers suggest logd output is being rewritten before apps inspect it.")

                            SelinuxAuditIntegrityState.EXPOSED ->
                                add("Recent audit evidence exposed readable SELinux AVC denial lines, which indicates audit side-channel leakage rather than direct root-process proof.")

                            SelinuxAuditIntegrityState.RESIDUE ->
                                add("Readable auditpatch residue suggests the audit surface may be rewritten.")

                            SelinuxAuditIntegrityState.INCONCLUSIVE ->
                                add("Audit rewrite checks remained non-proving from the current app context.")

                            SelinuxAuditIntegrityState.CLEAR, null -> Unit
                        }
                    }
                    val contextNote = when (contextValidity?.status) {
                        SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT ->
                            "The context validity oracle accepted both KSU-specific contexts from the current carrier."

                        SelinuxContextValidityProbe.BITPAIR_CLEAN ->
                            "The context validity oracle rejected both KSU-specific contexts in live policy."

                        SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED ->
                            if (repeatabilityFailed) {
                                "The context validity oracle repeated inconsistently, so its KSU verdict was not trusted."
                            } else {
                                "The context validity oracle failed its self-test, so its KSU verdict was not trusted."
                            }

                        SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS ->
                            "The context validity oracle split across the two KSU-specific contexts."

                        SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED ->
                            when (appZygoteCarrierState) {
                                AppZygoteCarrierSupportState.UNTRUSTED ->
                                    buildString {
                                        append("The dedicated app_zygote carrier did not land in the expected app_zygote context, so app_zygote-only SELinux evidence was not trusted.")
                                        contextValidity.details?.let {
                                            append(' ')
                                            append(it)
                                        }
                                    }
                                AppZygoteCarrierSupportState.FAILED ->
                                    buildString {
                                        append("The dedicated app_zygote carrier failed before the oracle produced a trusted result, so app_zygote-only SELinux coverage was reduced.")
                                        contextValidity.details?.let {
                                            append(' ')
                                            append(it)
                                        }
                                    }
                                AppZygoteCarrierSupportState.AVAILABLE ->
                                    contextValidity.details ?: "The context validity oracle stayed unavailable."
                            }

                        else -> null
                    }
                    listOf(base)
                        .plus(extra)
                        .plus(contextNote?.let { listOf(it) }.orEmpty())
                        .joinToString(" ")
                }

                SelinuxMode.PERMISSIVE ->
                    "SELinux todavía etiqueta actividad, pero las violaciones se registran en lugar de bloquearse."

                SelinuxMode.DISABLED ->
                    "El control de acceso obligatorio está desactivado; SELinux ya no restringe los procesos."

                SelinuxMode.UNKNOWN ->
                    "Local probes did not resolve a stable SELinux mode."
            }
        }
    }

    private fun buildHeaderFacts(report: SelinuxReport): List<SelinuxHeaderFactModel> {
        val policy = report.policyAnalysis
        return listOf(
            SelinuxHeaderFactModel(
                label = "Mode",
                value = report.resolvedStatusLabel,
                status = modeStatus(report.mode),
            ),
            SelinuxHeaderFactModel(
                label = "Policy",
                value = policyWeaknessLabel(policy?.weakness),
                status = policyWeaknessStatus(policy?.weakness),
            ),
            SelinuxHeaderFactModel(
                label = "Audit",
                value = auditIntegrityLabel(report.auditIntegrity),
                status = auditIntegrityStatus(report.auditIntegrity),
            ),
            SelinuxHeaderFactModel(
                label = "Context",
                value = report.contextType ?: "Desconocido",
                status = when {
                    policy?.dangerousTypesFound?.isNotEmpty() == true -> DetectorStatus.danger()
                    report.contextType != null -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
        )
    }

    private fun buildStateRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        val detectionPath = when {
            report.paradoxDetected -> "Paradox logic"
            report.methods.any {
                it.status.equals(
                    "Enforcing",
                    ignoreCase = true
                )
            } -> "Confirmación directa"

            else -> "Inferencia de respaldo"
        }
        return listOf(
            SelinuxDetailRowModel(
                label = "Mode",
                value = report.resolvedStatusLabel,
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "Policy enforced",
                value = when (report.mode) {
                    SelinuxMode.ENFORCING -> "Yes"
                    SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> "No"
                    SelinuxMode.UNKNOWN -> "Desconocido"
                },
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "MAC active",
                value = when (report.mode) {
                    SelinuxMode.ENFORCING -> "Yes"
                    SelinuxMode.PERMISSIVE -> "Solo registro"
                    SelinuxMode.DISABLED -> "No"
                    SelinuxMode.UNKNOWN -> "Desconocido"
                },
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "Filesystem",
                value = if (report.filesystemMounted) "Mounted" else "Missing",
                status = if (report.filesystemMounted) DetectorStatus.allClear() else DetectorStatus.danger(),
            ),
            SelinuxDetailRowModel(
                label = "Detection path",
                value = detectionPath,
                status = DetectorStatus.allClear(),
            ),
            SelinuxDetailRowModel(
                label = "Process context",
                value = report.contextType ?: "Desconocido",
                status = if (report.processContext != null) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
                detail = report.processContext,
            ),
        )
    }

    private fun buildImpactItems(report: SelinuxReport): List<SelinuxImpactItemModel> {
        val contextValidity = contextValidityResult(report)
        val procAttrCurrent = procAttrCurrentResult(report)
        val policyloadSeqno = policyloadSeqnoResult(report)
        val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
        val repeatabilityFailed =
            contextValidity?.details?.contains("repeatability failed", ignoreCase = true) == true
        val appZygoteCarrierState = contextValiditySupportState(contextValidity)
        if (report.stage != SelinuxStage.READY) {
            return when (report.stage) {
                SelinuxStage.LOADING -> listOf(
                    SelinuxImpactItemModel(
                        text = "Recolectando evidencia de estado local.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                SelinuxStage.FAILED -> listOf(
                    SelinuxImpactItemModel(
                        text = report.errorMessage ?: "Escaneo fallido.",
                        status = DetectorStatus.info(InfoKind.ERROR),
                    ),
                )

                SelinuxStage.READY -> emptyList()
            }
        }

        val items = mutableListOf<SelinuxImpactItemModel>()
        when (report.mode) {
            SelinuxMode.ENFORCING -> {
                items += SelinuxImpactItemModel(
                    "El control de acceso obligatorio está activo.",
                    DetectorStatus.allClear()
                )
                items += SelinuxImpactItemModel(
                    "Las violaciones de política deben ser bloqueadas y registradas.",
                    DetectorStatus.allClear()
                )
                if (report.paradoxDetected) {
                    items += SelinuxImpactItemModel(
                        "Permission-denied probes acted as positive evidence for enforcing mode.",
                        DetectorStatus.allClear(),
                    )
                }
                when (report.auditIntegrity?.state) {
                    SelinuxAuditIntegrityState.TAMPERED -> items += SelinuxImpactItemModel(
                        "Audit logs appear rewritten, so SELinux denials may look normal even when privileged contexts are present.",
                        DetectorStatus.danger(),
                    )

                    SelinuxAuditIntegrityState.EXPOSED -> items += SelinuxImpactItemModel(
                        "Readable SELinux AVC denial lines leaked through the audit surface. This is audit-surface exposure, not direct proof of a root daemon.",
                        DetectorStatus.warning(),
                    )

                    SelinuxAuditIntegrityState.RESIDUE -> items += SelinuxImpactItemModel(
                        "Readable auditpatch residue suggests audit denials could be relabeled or masked.",
                        DetectorStatus.warning(),
                    )

                    SelinuxAuditIntegrityState.INCONCLUSIVE -> items += SelinuxImpactItemModel(
                        "Las verificaciones de reescritura de audit estuvieron parcialmente no disponibles desde este contexto de app.",
                        DetectorStatus.info(InfoKind.SUPPORT),
                    )

                    SelinuxAuditIntegrityState.CLEAR, null -> Unit
                }
                when (report.policyAnalysis?.weakness) {
                    SelinuxPolicyWeakness.MODERATE -> items += SelinuxImpactItemModel(
                        "La deriva de política puede permitir que algunas restricciones sean evitadas.",
                        DetectorStatus.warning(),
                    )

                    SelinuxPolicyWeakness.SEVERE -> items += SelinuxImpactItemModel(
                        "La política parece muy debilitada; el cumplimiento puede ser inefectivo.",
                        DetectorStatus.danger(),
                    )

                    else -> Unit
                }
            }

            SelinuxMode.PERMISSIVE -> {
                items += SelinuxImpactItemModel(
                    "Las violaciones se registran pero no se bloquean.",
                    DetectorStatus.danger(),
                )
                items += SelinuxImpactItemModel(
                    "Apps sensibles a seguridad y verificaciones de integridad pueden fallar.",
                    DetectorStatus.danger(),
                )
            }

            SelinuxMode.DISABLED -> {
                items += SelinuxImpactItemModel(
                    "El control de acceso obligatorio está completamente deshabilitado.",
                    DetectorStatus.danger(),
                )
                items += SelinuxImpactItemModel(
                    "El dispositivo probablemente está muy modificado o comprometido.",
                    DetectorStatus.danger(),
                )
            }

            SelinuxMode.UNKNOWN -> {
                items += SelinuxImpactItemModel(
                    "Local probes were inconclusive.",
                    DetectorStatus.info(InfoKind.ERROR),
                )
            }
        }

        when (contextValidity?.status) {
            SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT -> items += SelinuxImpactItemModel(
                "The app_zygote carrier validated both KSU-specific contexts in live policy.",
                DetectorStatus.danger(),
            )

            SelinuxContextValidityProbe.BITPAIR_CLEAN -> items += SelinuxImpactItemModel(
                "The app_zygote carrier rejected both KSU-specific contexts.",
                DetectorStatus.allClear(),
            )

            SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED -> items += SelinuxImpactItemModel(
                if (repeatabilityFailed) {
                    "The context validity oracle repeated inconsistently, so its KSU verdict was not trusted."
                } else {
                    "The context validity oracle failed its self-test, so its KSU verdict was not trusted."
                },
                DetectorStatus.warning(),
            )

            SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS -> items += SelinuxImpactItemModel(
                "The context validity oracle split across the two KSU-specific contexts.",
                DetectorStatus.warning(),
            )

            SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED -> items += SelinuxImpactItemModel(
                contextValidity.details ?: "The context validity oracle stayed unavailable.",
                when (appZygoteCarrierState) {
                    AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                    AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                    AppZygoteCarrierSupportState.AVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            )

            else -> Unit
        }
        when {
            policyloadSeqno?.isSecure == false -> items += SelinuxImpactItemModel(
                "The zygotePreload app_zygote carrier observed a policyload/access seqno split.",
                DetectorStatus.danger(),
            )

            policyloadSeqno?.isSecure == true -> items += SelinuxImpactItemModel(
                "The zygotePreload app_zygote carrier reported a coherent policyload/access seqno contract.",
                DetectorStatus.allClear(),
            )

            policyloadSeqno != null -> items += SelinuxImpactItemModel(
                policyloadSeqno.details ?: "The zygotePreload app_zygote seqno oracle stayed unavailable.",
                DetectorStatus.info(InfoKind.SUPPORT),
            )
        }
        when {
            procAttrCurrent?.isSecure == false -> items += SelinuxImpactItemModel(
                "The dedicated app_zygote carrier observed anomalous /proc/self/attr/current writes for ${procAttrCurrent.status.removePrefix("Detected: ")}.",
                DetectorStatus.danger(),
            )

            procAttrCurrent?.isSecure == true -> items += SelinuxImpactItemModel(
                "El carrier app_zygote dedicado rechazó los contextos privilegiados probados con resultados EINVAL normales.",
                DetectorStatus.allClear(),
            )

            procAttrCurrent != null -> items += SelinuxImpactItemModel(
                procAttrCurrent.details ?: "The dedicated app_zygote attr/current write probe stayed unavailable.",
                DetectorStatus.info(InfoKind.SUPPORT),
            )
        }
        if (dirtyPolicyHit != null) {
            items += SelinuxImpactItemModel(
                trustedPolicyRuleImpact(dirtyPolicyHit),
                DetectorStatus.danger(),
            )
        }
        return items
    }

    private fun buildMethodRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        val msdRows = report.methods.filter { isMsdPolicyRuleMethod(it.method) }
        val droidspacesRows = report.methods.filter { isDroidspacesPolicyRuleMethod(it.method) }
        var msdInserted = false
        var droidspacesInserted = false
        return buildList {
            report.methods.forEach { result ->
                if (isMsdPolicyRuleMethod(result.method)) {
                    if (!msdInserted) {
                        buildAggregatedMsdMethodRow(msdRows)?.let(::add)
                        msdInserted = true
                    }
                } else if (isDroidspacesPolicyRuleMethod(result.method)) {
                    if (!droidspacesInserted) {
                        buildAggregatedDroidspacesMethodRow(droidspacesRows)?.let(::add)
                        droidspacesInserted = true
                    }
                } else {
                    add(methodRow(result))
                }
            }
        }
    }

    private fun methodRow(result: SelinuxCheckResult): SelinuxDetailRowModel {
        return SelinuxDetailRowModel(
            label = result.method,
            value = result.status,
            status = methodStatus(result),
            detail = result.details,
        )
    }

    private fun buildAggregatedMsdMethodRow(results: List<SelinuxCheckResult>): SelinuxDetailRowModel? {
        if (results.isEmpty()) {
            return null
        }
        val allowed = results.filter { it.status == "Allowed" }.map { msdPolicyRuleName(it.method) }
        val denied = results.filter { it.status == "Denied" }.map { msdPolicyRuleName(it.method) }
        val unavailable = results.filter { it.status == "No disponible" }.map { msdPolicyRuleName(it.method) }
        val aggregateResult = SelinuxCheckResult(
            method = "Dirty sepolicy rule: MSD",
            status = when {
                allowed.isNotEmpty() -> "Allowed"
                unavailable.isNotEmpty() -> "No disponible"
                else -> "Denied"
            },
            isSecure = when {
                allowed.isNotEmpty() -> false
                unavailable.isNotEmpty() -> null
                else -> true
            },
            permissionDenied = results.all { it.permissionDenied },
            details = null,
            dirtyPolicyTrusted = results.any { it.dirtyPolicyTrusted },
        )
        return SelinuxDetailRowModel(
            label = aggregateResult.method,
            value = buildList {
                if (allowed.isNotEmpty()) {
                    add("${allowed.size} allowed")
                }
                if (denied.isNotEmpty()) {
                    add("${denied.size} denied")
                }
                if (unavailable.isNotEmpty()) {
                    add("${unavailable.size} unavailable")
                }
            }.joinToString(", "),
            status = methodStatus(aggregateResult),
            detail = buildList {
                if (allowed.isNotEmpty()) {
                    add("Allowed: ${allowed.joinToString()}")
                }
                if (denied.isNotEmpty()) {
                    add("Denied: ${denied.joinToString()}")
                }
                if (unavailable.isNotEmpty()) {
                    add("Unavailable: ${unavailable.joinToString()}")
                }
            }.joinToString(" | "),
        )
    }

    private fun buildAggregatedDroidspacesMethodRow(results: List<SelinuxCheckResult>): SelinuxDetailRowModel? {
        if (results.isEmpty()) {
            return null
        }
        val allowed = results.filter { it.status == "Allowed" }.map { droidspacesPolicyRuleName(it.method) }
        val denied = results.filter { it.status == "Denied" }.map { droidspacesPolicyRuleName(it.method) }
        val unavailable = results.filter { it.status == "No disponible" }.map { droidspacesPolicyRuleName(it.method) }
        val aggregateResult = SelinuxCheckResult(
            method = "Dirty sepolicy rule: Droidspaces",
            status = when {
                allowed.isNotEmpty() -> "Allowed"
                unavailable.isNotEmpty() -> "No disponible"
                else -> "Denied"
            },
            isSecure = when {
                allowed.isNotEmpty() -> false
                unavailable.isNotEmpty() -> null
                else -> true
            },
            permissionDenied = results.all { it.permissionDenied },
            details = null,
            dirtyPolicyTrusted = results.any { it.dirtyPolicyTrusted },
        )
        return SelinuxDetailRowModel(
            label = aggregateResult.method,
            value = buildList {
                if (allowed.isNotEmpty()) {
                    add("${allowed.size} allowed")
                }
                if (denied.isNotEmpty()) {
                    add("${denied.size} denied")
                }
                if (unavailable.isNotEmpty()) {
                    add("${unavailable.size} unavailable")
                }
            }.joinToString(", "),
            status = methodStatus(aggregateResult),
            detail = buildList {
                if (allowed.isNotEmpty()) {
                    add("Allowed: ${allowed.joinToString()}")
                }
                if (denied.isNotEmpty()) {
                    add("Denied: ${denied.joinToString()}")
                }
                if (unavailable.isNotEmpty()) {
                    add("Unavailable: ${unavailable.joinToString()}")
                }
            }.joinToString(" | "),
        )
    }

    private fun buildPolicyRows(policy: SelinuxPolicyAnalysis?): List<SelinuxDetailRowModel> {
        if (policy == null) {
            return emptyList()
        }
        return listOf(
            SelinuxDetailRowModel(
                label = "Strength",
                value = policyWeaknessLabel(policy.weakness),
                status = policyWeaknessStatus(policy.weakness),
            ),
            SelinuxDetailRowModel(
                label = "Policy version",
                value = policy.policyVersion?.toString() ?: "Unreadable",
                status = when {
                    policy.policyVersion == null -> DetectorStatus.info(InfoKind.SUPPORT)
                    policy.policyVersionOk -> DetectorStatus.allClear()
                    else -> DetectorStatus.warning()
                },
            ),
            SelinuxDetailRowModel(
                label = "Security classes",
                value = policyClassValue(policy),
                status = policyClassStatus(policy),
                detail = if (policy.classCount == 0 && policy.foundClasses.isEmpty()) {
                    "Class directory unreadable from the current app context."
                } else if (policy.missingClasses.isNotEmpty()) {
                    "Missing: ${policy.missingClasses.joinToString()}"
                } else {
                    null
                },
            ),
            SelinuxDetailRowModel(
                label = "Process context",
                value = policy.contextType ?: "Desconocido",
                status = if (policy.dangerousTypesFound.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                detail = policy.processContext,
            ),
            SelinuxDetailRowModel(
                label = "Dangerous types",
                value = if (policy.dangerousTypesFound.isEmpty()) "Ninguno" else policy.dangerousTypesFound.joinToString(),
                status = if (policy.dangerousTypesFound.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
            ),
            SelinuxDetailRowModel(
                label = "Permissive domains",
                value = if (policy.permissiveDomains.isEmpty()) "Ninguno" else policy.permissiveDomains.joinToString(),
                status = if (policy.permissiveDomains.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
            ),
        )
    }

    private fun buildPolicyNotes(policy: SelinuxPolicyAnalysis?): List<SelinuxImpactItemModel> {
        return policy?.details?.map { detail ->
            SelinuxImpactItemModel(
                text = detail,
                status = when {
                    detail.contains("below minimum", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("missing", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("dangerous", ignoreCase = true) -> DetectorStatus.danger()
                    detail.contains("permissive", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("normal", ignoreCase = true) -> DetectorStatus.allClear()
                    detail.contains("meets minimum", ignoreCase = true) -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            )
        }.orEmpty()
    }

    private fun buildAuditRows(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxDetailRowModel> {
        if (analysis == null) {
            return emptyList()
        }

        val rows = mutableListOf(
            SelinuxDetailRowModel(
                label = "Surface",
                value = auditIntegrityLabel(analysis),
                status = auditIntegrityStatus(analysis),
            ),
            SelinuxDetailRowModel(
                label = "Runtime markers",
                value = when {
                    analysis.runtimeHits.isNotEmpty() -> "${analysis.runtimeHits.size} hit(s)"
                    analysis.logcatChecked -> "No observado"
                    else -> "No disponible"
                },
                status = when {
                    analysis.runtimeHits.isNotEmpty() -> DetectorStatus.danger()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.runtimeHits.isNotEmpty() ->
                        "Known auditpatch runtime markers surfaced in recent auditd event logs."

                    analysis.logcatChecked ->
                        "Recent auditd event logs were readable, but absence of markers is not proof of a clean audit surface."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "AVC side-channel",
                value = when {
                    analysis.sideChannelHits.isNotEmpty() -> "${analysis.sideChannelHits.size} hit(s)"
                    analysis.logcatChecked -> "No observado"
                    else -> "No disponible"
                },
                status = when {
                    analysis.sideChannelHits.isNotEmpty() -> DetectorStatus.warning()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.sideChannelHits.isNotEmpty() ->
                        "Readable auditd event logs exposed the same nonce-tagged controlled AVC denial seen by the direct libselinux callback probe."

                    analysis.directProbeUsed && analysis.logcatChecked ->
                        "No matching nonce-tagged controlled AVC denial surfaced in the readable auditd event window."

                    analysis.logcatChecked ->
                        "No matching controlled AVC denial surfaced in the readable auditd event window, but absence is not proof."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "su-related AVC",
                value = when {
                    analysis.suspiciousActorHits.isNotEmpty() -> "${analysis.suspiciousActorHits.size} hit(s)"
                    analysis.logcatChecked -> "No observado"
                    else -> "No disponible"
                },
                status = when {
                    analysis.suspiciousActorHits.isNotEmpty() -> DetectorStatus.warning()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.suspiciousActorHits.isNotEmpty() ->
                        "Readable AVC denials referenced su/magisk/ksud-related actor strings in comm, exe, path, or name fields."

                    analysis.logcatChecked ->
                        "No su-related actor string surfaced in the readable canonical AVC window."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "Residue paths",
                value = if (analysis.residueHits.isNotEmpty()) "${analysis.residueHits.size} hit(s)" else "Ninguno",
                status = when {
                    analysis.residueHits.any { it.strongSignal } -> DetectorStatus.warning()
                    analysis.residueHits.isNotEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
                detail = if (analysis.residueHits.isNotEmpty()) {
                    "Readable module residue matched common ZN-AuditPatch locations."
                } else {
                    "No readable auditpatch residue surfaced under common module paths."
                },
            ),
        )

        analysis.runtimeHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = if (hit.strongSignal) DetectorStatus.danger() else DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.sideChannelHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.suspiciousActorHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.residueHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = "Readable",
                status = if (hit.strongSignal) DetectorStatus.warning() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
                detail = listOfNotNull(hit.value, hit.detail).joinToString(" | "),
            )
        }
        return rows
    }

    private fun buildAuditNotes(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxImpactItemModel> {
        return analysis?.notes?.map { note ->
            SelinuxImpactItemModel(
                text = note,
                status = when {
                    note.contains("rewrite markers", ignoreCase = true) -> DetectorStatus.danger()
                    note.contains("side-channel", ignoreCase = true) -> DetectorStatus.warning()
                    note.contains("su-related actor", ignoreCase = true) -> DetectorStatus.warning()
                    note.contains(
                        "Readable auditpatch residue",
                        ignoreCase = true
                    ) -> DetectorStatus.warning()

                    note.contains("did not expose", ignoreCase = true) -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            )
        }.orEmpty()
    }

    private fun buildDeviceRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        return listOf(
            SelinuxDetailRowModel(
                label = "Android",
                value = if (report.androidVersion.isNotBlank()) report.androidVersion else "Desconocido",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            SelinuxDetailRowModel(
                label = "API level",
                value = if (report.apiLevel > 0) report.apiLevel.toString() else "Desconocido",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            SelinuxDetailRowModel(
                label = "Required since",
                value = "Android 5.0 (API 21)",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )
    }

    private fun buildReferences(): List<String> {
        return listOf(
            "Paradoja SELinux: un permiso denegado puede probar el modo enforcing.",
            "El modo enforcing bloquea las acciones no permitidas en lugar de solo registrarlas.",
            "Se espera que los dispositivos Android de producción ejecuten SELinux en modo enforcing.",
            "app_zygote can query SELinux context validity through selinux_check_context, which ultimately writes to /sys/fs/selinux/context.",
            "A dedicated app_zygote carrier can also probe privileged context materialization by writing candidate labels to /proc/self/attr/current and classifying non-EINVAL outcomes.",
            "The policyload/access seqno oracle must be captured inside zygotePreloadName; the isolated child may lose app_zygote SELinuxfs access and should downgrade missing coverage to info.",
            "Audit or log surfaces can be rewritten in user space, so missing suspicious tcontext values is not always proof.",
            "Readable AVC denial lines should be treated as audit-surface leakage, not as direct proof of a root process.",
            "comm, exe, path, and name fields inside AVC logs are supporting hints, not standalone proof of a live su daemon.",
        )
    }

    private fun policyWeaknessLabel(weakness: SelinuxPolicyWeakness?): String {
        return when (weakness) {
            SelinuxPolicyWeakness.NONE -> "Strong"
            SelinuxPolicyWeakness.MINOR -> "Deriva menor"
            SelinuxPolicyWeakness.MODERATE -> "Review"
            SelinuxPolicyWeakness.SEVERE -> "Weak"
            null -> "Omitido"
        }
    }

    private fun policyWeaknessStatus(weakness: SelinuxPolicyWeakness?): DetectorStatus {
        return when (weakness) {
            SelinuxPolicyWeakness.NONE -> DetectorStatus.allClear()
            SelinuxPolicyWeakness.MINOR -> DetectorStatus.info(InfoKind.SUPPORT)
            SelinuxPolicyWeakness.MODERATE -> DetectorStatus.warning()
            SelinuxPolicyWeakness.SEVERE -> DetectorStatus.danger()
            null -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: SelinuxCheckResult): DetectorStatus {
        if (result.method == SelinuxContextValidityProbe.METHOD_LABEL) {
            return when (result.status) {
                SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT -> DetectorStatus.danger()
                SelinuxContextValidityProbe.BITPAIR_CLEAN -> DetectorStatus.allClear()
                SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS -> DetectorStatus.warning()
                SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED -> DetectorStatus.warning()
                else -> when (contextValiditySupportState(result)) {
                    AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                    AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                    AppZygoteCarrierSupportState.AVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
                }
            }
        }
        if (result.method == SelinuxProcAttrCurrentProbe.METHOD_LABEL) {
            return when {
                result.isSecure == false -> DetectorStatus.danger()
                result.isSecure == true -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            }
        }
        if (result.method == SelinuxPolicyloadSeqnoProbe.METHOD_LABEL) {
            return when {
                result.isSecure == false -> DetectorStatus.danger()
                result.isSecure == true -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            }
        }
        return when {
            result.permissionDenied -> DetectorStatus.allClear()
            result.isSecure == true -> DetectorStatus.allClear()
            result.isSecure == false -> DetectorStatus.danger()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun policyClassValue(policy: SelinuxPolicyAnalysis?): String {
        return when {
            policy == null -> "—"
            policy.classCount == 0 && policy.foundClasses.isEmpty() -> "Unreadable"
            else -> policy.classCount.toString()
        }
    }

    private fun policyClassStatus(policy: SelinuxPolicyAnalysis?): DetectorStatus {
        return when {
            policy == null -> DetectorStatus.info(InfoKind.SUPPORT)
            policy.classCount == 0 && policy.foundClasses.isEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
            policy.classCountOk -> DetectorStatus.allClear()
            else -> DetectorStatus.warning()
        }
    }

    private fun auditIntegrityLabel(analysis: SelinuxAuditIntegrityAnalysis?): String {
        return when (analysis?.state) {
            SelinuxAuditIntegrityState.CLEAR -> "Sin señal"
            SelinuxAuditIntegrityState.RESIDUE -> "Residue"
            SelinuxAuditIntegrityState.EXPOSED -> "Expuesto"
            SelinuxAuditIntegrityState.TAMPERED -> "Modificado"
            SelinuxAuditIntegrityState.INCONCLUSIVE -> "Inconcluso"
            null -> "Omitido"
        }
    }

    private fun auditIntegrityStatus(analysis: SelinuxAuditIntegrityAnalysis?): DetectorStatus {
        return when (analysis?.state) {
            SelinuxAuditIntegrityState.CLEAR -> DetectorStatus.allClear()
            SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()
            SelinuxAuditIntegrityState.EXPOSED -> DetectorStatus.warning()
            SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
            SelinuxAuditIntegrityState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
            null -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun modeStatus(mode: SelinuxMode): DetectorStatus {
        return when (mode) {
            SelinuxMode.ENFORCING -> DetectorStatus.allClear()
            SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
            SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
        }
    }

    private fun contextValidityResult(report: SelinuxReport): SelinuxCheckResult? {
        return report.methods.firstOrNull { it.method == SelinuxContextValidityProbe.METHOD_LABEL }
    }

    private fun procAttrCurrentResult(report: SelinuxReport): SelinuxCheckResult? {
        return report.methods.firstOrNull { it.method == SelinuxProcAttrCurrentProbe.METHOD_LABEL }
    }

    private fun policyloadSeqnoResult(report: SelinuxReport): SelinuxCheckResult? {
        return report.methods.firstOrNull { it.method == SelinuxPolicyloadSeqnoProbe.METHOD_LABEL }
    }

    private fun SelinuxReport.toDetectorStatus(): DetectorStatus {
        val contextValidity = contextValidityResult(this)
        val procAttrCurrent = procAttrCurrentResult(this)
        val policyloadSeqno = policyloadSeqnoResult(this)
        val dirtyPolicyHit = firstTrustedPolicyRuleHit(this)
        val appZygoteCarrierState = contextValiditySupportState(contextValidity)
        return when (stage) {
            SelinuxStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            SelinuxStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            SelinuxStage.READY -> when (mode) {
                SelinuxMode.ENFORCING -> when {
                    auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT -> DetectorStatus.danger()
                    policyloadSeqno?.isSecure == false -> DetectorStatus.danger()
                    procAttrCurrent?.isSecure == false -> DetectorStatus.danger()
                    dirtyPolicyHit != null -> DetectorStatus.warning()
                    appZygoteCarrierState == AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                    appZygoteCarrierState == AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED -> DetectorStatus.warning()
                    contextValidity?.status == SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS -> DetectorStatus.warning()
                    policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE ||
                            policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE ||
                            auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED ||
                            auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()

                    else -> DetectorStatus.allClear()
                }

                SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
                SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
            }
        }
    }

    private fun firstTrustedPolicyRuleHit(report: SelinuxReport): SelinuxCheckResult? {
        return report.methods.firstOrNull {
            isPolicyRuleMethod(it.method) &&
                it.status == "Allowed" &&
                it.isSecure == false &&
                it.dirtyPolicyTrusted
        }
    }

    private fun isPolicyRuleMethod(method: String): Boolean {
        return method.startsWith("Dirty sepolicy rule: ") ||
            method.startsWith("Droidspaces checker: ") ||
            method.startsWith("MSD checker: ")
    }

    private fun isMsdPolicyRuleMethod(method: String): Boolean {
        return method.startsWith("MSD checker: ")
    }

    private fun isDroidspacesPolicyRuleMethod(method: String): Boolean {
        return method.startsWith("Droidspaces checker: ")
    }

    private fun policyRuleDisplayName(method: String): String {
        return when {
            method.startsWith("Dirty sepolicy rule: ") -> method.removePrefix("Dirty sepolicy rule: ")
            method.startsWith("Droidspaces checker: ") -> "Droidspaces: ${method.removePrefix("Droidspaces checker: ")}"
            method.startsWith("MSD checker: ") -> "MSD: ${method.removePrefix("MSD checker: ")}"
            else -> method
        }
    }

    private fun msdPolicyRuleName(method: String): String {
        return method.removePrefix("MSD checker: ")
    }

    private fun droidspacesPolicyRuleName(method: String): String {
        return method.removePrefix("Droidspaces checker: ")
    }

    private fun trustedPolicyRuleVerdict(): String {
        return "Activo con regla sepolicy modificada"
    }

    private fun trustedPolicyRuleSummary(result: SelinuxCheckResult): String {
        return "A trusted DirtySepolicy-style access query reported ${policyRuleDisplayName(result.method)} as allowed."
    }

    private fun trustedPolicyRuleImpact(result: SelinuxCheckResult): String {
        return "A trusted DirtySepolicy-style access rule was allowed: ${policyRuleDisplayName(result.method)}."
    }

    private fun contextValiditySupportState(result: SelinuxCheckResult?): AppZygoteCarrierSupportState {
        if (result?.method != SelinuxContextValidityProbe.METHOD_LABEL ||
            result.status != SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED
        ) {
            return AppZygoteCarrierSupportState.AVAILABLE
        }
        return when {
            result.details.orEmpty().contains("Carrier state=untrusted") ->
                AppZygoteCarrierSupportState.UNTRUSTED
            result.details.orEmpty().contains("Carrier state=failed") ->
                AppZygoteCarrierSupportState.FAILED
            else -> AppZygoteCarrierSupportState.AVAILABLE
        }
    }

    private enum class AppZygoteCarrierSupportState {
        AVAILABLE,
        FAILED,
        UNTRUSTED,
    }
}
