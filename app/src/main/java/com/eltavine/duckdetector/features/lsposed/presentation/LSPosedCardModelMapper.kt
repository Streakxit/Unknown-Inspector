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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedHeaderFactModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedImpactItemModel

class LSPosedCardModelMapper {

    fun map(report: LSPosedReport): LSPosedCardModel {
        return LSPosedCardModel(
            title = "LSPosed",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            runtimeRows = buildRowsForGroup(report, LSPosedSignalGroup.RUNTIME, "Runtime probes"),
            binderRows = buildRowsForGroup(report, LSPosedSignalGroup.BINDER, "Binder probes"),
            packageRows = buildRowsForGroup(report, LSPosedSignalGroup.PACKAGES, "Packages"),
            policyRows = buildRowsForGroup(report, LSPosedSignalGroup.POLICY, "SELinux policy"),
            nativeRows = buildRowsForGroup(report, LSPosedSignalGroup.NATIVE, "Native traces"),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING -> "class + classloader + bridge fields + callbacks + runtime + logcat + binder + zygote gids + policy + native"
            LSPosedStage.FAILED -> "local LSPosed/Xposed scan failed"
            LSPosedStage.READY -> {
                buildList {
                    add("${report.managerPackageCount} manager")
                    add("${report.moduleAppCount} module")
                    add("${report.nativeTraceCount} native")
                    if (report.dirtyPolicyAvailable || report.policySignalCount > 0) {
                        add("${report.policySignalCount} policy")
                    }
                }.joinToString(" · ")
            }
        }
    }

    private fun buildVerdict(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING -> "Scanning LSPosed/Xposed runtime and residue"
            LSPosedStage.FAILED -> "LSPosed scan failed"
            LSPosedStage.READY -> when {
                report.hasLsposedPolicySignal() -> "Dirty SELinux policy exposes LSPosed rule"
                report.hasDangerSignals -> "${report.dangerSignalCount} high-risk LSPosed signal(s)"
                report.hasPolicySignals() -> "Dirty SELinux policy signal(s)"
                report.hasWarningSignals -> "${report.warningSignalCount} LSPosed residue signal(s)"
                report.hasReducedCoverage() -> "LSPosed scan has reduced coverage"
                else -> "No LSPosed/Xposed runtime signal"
            }
        }
    }

    private fun buildSummary(report: LSPosedReport): String {
        return when (report.stage) {
            LSPosedStage.LOADING ->
                "Class loading, ClassLoader chains, XposedBridge fields, callbacks, package metadata, stack traces, Binder bridges, zygote permission GID audits, runtime artifacts, logcat leaks, and LSPosed-specific native traces are collecting local evidence."

            LSPosedStage.FAILED ->
                report.errorMessage
                    ?: "La detección de LSPosed falló antes de recolectar evidencia."

            LSPosedStage.READY -> when {
                report.hasDangerSignals ->
                    "Binder bridge replies, loaded Xposed classes, XposedBridge fields, callback handlers, runtime artifacts, logcat leaks, zygote permission GID mismatches, dirty SELinux policy rules, stack trace signatures, or native LSPosed keywords point to active hook-framework presence rather than passive install residue."

                report.hasWarningSignals ->
                    "Installed managers, deep ClassLoader chains, environment residue, dirty SELinux policy drift, or pattern-only logcat traces were found, but the current process did not expose enough stronger runtime evidence to treat the framework as confirmed active here."

                report.hasReducedCoverage() ->
                    "No LSPosed/Xposed signal surfaced from the available probes, but at least one runtime, package, logcat, or native evidence path was unavailable."

                else ->
                    "No Xposed class loading, ClassLoader, callback, Binder bridge, runtime artifact, logcat, stack, maps, or heap traces surfaced in the current app process."
            }
        }
    }

    private fun buildHeaderFacts(report: LSPosedReport): List<LSPosedHeaderFactModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderFacts(
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            LSPosedStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            LSPosedStage.READY -> listOf(
                LSPosedHeaderFactModel(
                    label = "Critical",
                    value = countLabel(report.dangerSignalCount, report.hasReducedCoverage()),
                    status = when {
                        report.dangerSignalCount > 0 -> DetectorStatus.danger()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedHeaderFactModel(
                    label = "Review",
                    value = countLabel(report.warningSignalCount, report.hasReducedCoverage()),
                    status = when {
                        report.warningSignalCount > 0 -> DetectorStatus.warning()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedHeaderFactModel(
                    label = "Bridge",
                    value = if (report.binderHitCount > 0) report.binderHitCount.toString() else "Limpio",
                    status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedHeaderFactModel(
                    label = "Paquetes",
                    value = when {
                        report.packageSignalCount > 0 -> report.packageSignalCount.toString()
                        report.packageVisibility == LSPosedPackageVisibility.FULL -> "Limpio"
                        else -> visibilityLabel(report.packageVisibility)
                    },
                    status = when {
                        report.packageSignalCount > 0 -> DetectorStatus.warning()
                        report.packageVisibility == LSPosedPackageVisibility.FULL -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildRowsForGroup(
        report: LSPosedReport,
        group: LSPosedSignalGroup,
        fallbackLabel: String,
    ): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente"
            )

            LSPosedStage.FAILED -> placeholderRows(
                listOf(fallbackLabel),
                DetectorStatus.info(InfoKind.ERROR),
                "Error"
            )

            LSPosedStage.READY -> {
                val rows = report.signals
                    .filter { it.group == group }
                    .map(::signalRow)
                if (rows.isNotEmpty()) {
                    rows
                } else if (report.sectionUnavailable(group)) {
                    listOf(
                        LSPosedDetailRowModel(
                            label = fallbackLabel,
                            value = if (group == LSPosedSignalGroup.PACKAGES) {
                                visibilityLabel(report.packageVisibility)
                            } else {
                                "No disponible"
                            },
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                            detail = "This LSPosed evidence slice was unavailable or scoped, so it is not treated as clean.",
                        ),
                    )
                } else {
                    listOf(
                        LSPosedDetailRowModel(
                            label = fallbackLabel,
                            value = "Limpio",
                            status = DetectorStatus.allClear(),
                            detail = "No se detectó señal en esta porción de evidencia LSPosed.",
                        ),
                    )
                }
            }
        }
    }

    private fun buildImpactItems(report: LSPosedReport): List<LSPosedImpactItemModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> listOf(
                LSPosedImpactItemModel(
                    text = "Recolectando evidencia de clases, Binder, artefactos de runtime y paquetes.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            LSPosedStage.FAILED -> listOf(
                LSPosedImpactItemModel(
                    text = report.errorMessage ?: "Escaneo de LSPosed fallido.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            LSPosedStage.READY -> when {
                report.hasDangerSignals -> listOf(
                    LSPosedImpactItemModel(
                        text = "Clases Xposed cargadas, campos bridge, respuestas Binder, artefactos de runtime, fugas logcat, reglas de política SELinux sucia y palabras clave LSPosed nativas son evidencia más fuerte que el residuo de paquetes porque tocan el proceso actual, la política activa o los servicios del sistema directamente.",
                        status = DetectorStatus.danger(),
                    ),
                    LSPosedImpactItemModel(
                        text = "Esta tarjeta solo observa una porción estrecha del runtime. Leéla junto con Memoria, Root Nativo, Montaje y Propiedades del Sistema cuando la configuración se esté ocultando activamente.",
                        status = DetectorStatus.warning(),
                    ),
                )

                report.hasWarningSignals -> listOf(
                    LSPosedImpactItemModel(
                        text = "Manager packages, Xposed module meta-data, or dirty SELinux policy drift show framework or root-policy residue, but they do not prove the current process is hooked right now.",
                        status = DetectorStatus.warning(),
                    ),
                    LSPosedImpactItemModel(
                        text = "Hardened setups can avoid exposing direct stack or class evidence in the current app, so yellow-only results still deserve correlation with other detector cards.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> if (report.hasReducedCoverage()) {
                    listOf(
                        LSPosedImpactItemModel(
                            text = "No LSPosed/Xposed signal surfaced from available probes, but one or more runtime evidence paths were unavailable.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                        LSPosedImpactItemModel(
                            text = "This support-only result lowers confidence only for the probes that actually ran.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                } else {
                    listOf(
                        LSPosedImpactItemModel(
                            text = "The current app process did not expose LSPosed/Xposed class loading, Binder bridge behavior, or LSPosed-native runtime strings.",
                            status = DetectorStatus.allClear(),
                        ),
                        LSPosedImpactItemModel(
                            text = "A clean result lowers confidence in active LSPosed-style hooking for this process, but it does not prove the whole device is stock.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                }
            }
        }
    }

    private fun buildMethodRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente"
            )

            LSPosedStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Error"
            )

            LSPosedStage.READY -> report.methods.map { method ->
                LSPosedDetailRowModel(
                    label = method.label,
                    value = method.summary,
                    status = methodStatus(method),
                    detail = method.detail,
                    detailMonospace = false,
                )
            }
        }
    }

    private fun buildScanRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
        return when (report.stage) {
            LSPosedStage.LOADING -> placeholderRows(
                listOf(
                    "Danger signals",
                    "Review signals",
                    "Detecciones de clase",
                    "Detecciones ClassLoader",
                    "Detecciones campo bridge",
                    "Detecciones de stack",
                    "Detecciones callback",
                    "Detecciones Binder",
                    "Detecciones artefactos runtime",
                    "Disponibilidad artefactos runtime",
                    "Detecciones logcat",
                    "Disponibilidad logcat",
                    "Detecciones política sucia",
                    "Disponibilidad política sucia",
                    "Paquetes manager",
                    "Apps de módulo",
                    "Mapas nativos",
                    "Heap nativo",
                    "Package visibility",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
            )

            LSPosedStage.FAILED -> placeholderRows(
                listOf(
                    "Danger signals",
                    "Review signals",
                    "Detecciones de clase",
                    "Detecciones ClassLoader",
                    "Detecciones campo bridge",
                    "Detecciones de stack",
                    "Detecciones callback",
                    "Detecciones Binder",
                    "Detecciones artefactos runtime",
                    "Disponibilidad artefactos runtime",
                    "Detecciones logcat",
                    "Disponibilidad logcat",
                    "Detecciones política sucia",
                    "Disponibilidad política sucia",
                    "Paquetes manager",
                    "Apps de módulo",
                    "Mapas nativos",
                    "Heap nativo",
                    "Package visibility",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            LSPosedStage.READY -> listOf(
                LSPosedDetailRowModel(
                    label = "Señales críticas",
                    value = report.dangerSignalCount.toString(),
                    status = when {
                        report.dangerSignalCount > 0 -> DetectorStatus.danger()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Señales de revisión",
                    value = report.warningSignalCount.toString(),
                    status = when {
                        report.warningSignalCount > 0 -> DetectorStatus.warning()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones de clase",
                    value = report.classHitCount.toString(),
                    status = if (report.classHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones ClassLoader",
                    value = report.classLoaderHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("classloader_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.classLoaderHitCount > 0 -> DetectorStatus.warning()
                        else -> DetectorStatus.allClear()
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones campo bridge",
                    value = report.bridgeFieldHitCount.toString(),
                    status = if (report.bridgeFieldHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones de stack",
                    value = report.stackHitCount.toString(),
                    status = if (report.stackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones callback",
                    value = report.callbackHitCount.toString(),
                    status = if (report.callbackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones Binder",
                    value = report.binderHitCount.toString(),
                    status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones artefactos runtime",
                    value = report.runtimeArtifactHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("runtime_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.runtimeArtifactHitCount > 0 -> DetectorStatus.warning()
                        report.runtimeArtifactAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Disponibilidad artefactos runtime",
                    value = if (report.runtimeArtifactAvailable) "Verificado" else "No disponible",
                    status = if (report.runtimeArtifactAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones logcat",
                    value = report.logcatHitCount.toString(),
                    status = when {
                        report.signals.any {
                            it.id.startsWith("logcat_") &&
                                    it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.logcatHitCount > 0 -> DetectorStatus.warning()
                        report.logcatAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Disponibilidad logcat",
                    value = if (report.logcatAvailable) "Verificado" else "No disponible",
                    status = if (report.logcatAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                LSPosedDetailRowModel(
                    label = "Detecciones política sucia",
                    value = report.policySignalCount.toString(),
                    status = when {
                        report.signals.any {
                            it.group == LSPosedSignalGroup.POLICY &&
                                it.severity == LSPosedSignalSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.policySignalCount > 0 -> DetectorStatus.warning()
                        report.dirtyPolicyAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Disponibilidad política sucia",
                    value = if (report.dirtyPolicyAvailable) "Verificado" else "No disponible",
                    status = if (report.dirtyPolicyAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                LSPosedDetailRowModel(
                    label = "Paquetes manager",
                    value = report.managerPackageCount.toString(),
                    status = if (report.managerPackageCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Apps de módulo",
                    value = report.moduleAppCount.toString(),
                    status = if (report.moduleAppCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
                ),
                LSPosedDetailRowModel(
                    label = "Mapas nativos",
                    value = if (report.nativeAvailable || report.nativeMapsHitCount > 0) {
                        report.nativeMapsHitCount.toString()
                    } else {
                        "N/A"
                    },
                    status = when {
                        report.nativeMapsHitCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Heap nativo",
                    value = if (report.nativeHeapAvailable || report.nativeHeapHitCount > 0) {
                        "${report.nativeHeapHitCount}/${report.nativeHeapScannedRegions}"
                    } else {
                        "N/A"
                    },
                    status = when {
                        report.nativeHeapHitCount > 0 -> DetectorStatus.danger()
                        report.nativeHeapAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                LSPosedDetailRowModel(
                    label = "Visibilidad de paquetes",
                    value = visibilityLabel(report.packageVisibility),
                    status = when (report.packageVisibility) {
                        LSPosedPackageVisibility.FULL -> DetectorStatus.allClear()
                        LSPosedPackageVisibility.RESTRICTED -> DetectorStatus.info(InfoKind.SUPPORT)
                        LSPosedPackageVisibility.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
                    },
                ),
            )
        }
    }

    private fun signalRow(signal: LSPosedSignal): LSPosedDetailRowModel {
        return LSPosedDetailRowModel(
            label = signal.label,
            value = signal.value,
            status = signalStatus(signal),
            detail = signal.detail,
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<LSPosedHeaderFactModel> {
        return listOf(
            LSPosedHeaderFactModel("Critical", value, status),
            LSPosedHeaderFactModel("Review", value, status),
            LSPosedHeaderFactModel("Bridge", value, status),
            LSPosedHeaderFactModel("Packages", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
    ): List<LSPosedDetailRowModel> {
        return labels.map { label ->
            LSPosedDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<LSPosedDetailRowModel> {
        return listOf(
            "Class load",
            "ClassLoader chain",
            "XposedBridge fields",
            "Package catalog",
            "Xposed meta-data",
            "Stack trace",
            "Hook callbacks",
            "Binder bridge",
            "Zygote permissions",
            "Runtime artifacts",
            "Logcat leaks",
            "Dirty sepolicy",
            "Mapas nativos",
            "Heap nativo",
            "Native library",
            "Resumen de señales",
        ).map { label ->
            LSPosedDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun countLabel(count: Int, reducedCoverage: Boolean = false): String {
        return when {
            count > 0 -> count.toString()
            reducedCoverage -> "N/A"
            else -> "Ninguno"
        }
    }

    private fun visibilityLabel(
        visibility: LSPosedPackageVisibility,
    ): String {
        return when (visibility) {
            LSPosedPackageVisibility.FULL -> "Completo"
            LSPosedPackageVisibility.RESTRICTED -> "Restricted"
            LSPosedPackageVisibility.UNKNOWN -> "Desconocido"
        }
    }

    private fun signalStatus(signal: LSPosedSignal): DetectorStatus {
        return when (signal.severity) {
            LSPosedSignalSeverity.DANGER -> DetectorStatus.danger()
            LSPosedSignalSeverity.WARNING -> DetectorStatus.warning()
        }
    }

    private fun methodStatus(method: LSPosedMethodResult): DetectorStatus {
        return when (method.outcome) {
            LSPosedMethodOutcome.CLEAN -> DetectorStatus.allClear()
            LSPosedMethodOutcome.WARNING -> DetectorStatus.warning()
            LSPosedMethodOutcome.DETECTED -> DetectorStatus.danger()
            LSPosedMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun LSPosedReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            LSPosedStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            LSPosedStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            LSPosedStage.READY -> when {
                hasDangerSignals -> DetectorStatus.danger()
                hasWarningSignals -> DetectorStatus.warning()
                hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }

    private fun LSPosedReport.hasReducedCoverage(): Boolean {
        return !nativeAvailable ||
                !nativeHeapAvailable ||
                !zygotePermissionAvailable ||
                !runtimeArtifactAvailable ||
                !logcatAvailable ||
                !dirtyPolicyAvailable ||
                packageVisibility != LSPosedPackageVisibility.FULL
    }

    private fun LSPosedReport.sectionUnavailable(group: LSPosedSignalGroup): Boolean {
        return when (group) {
            LSPosedSignalGroup.NATIVE -> !nativeAvailable || !nativeHeapAvailable
            LSPosedSignalGroup.PACKAGES -> packageVisibility != LSPosedPackageVisibility.FULL
            LSPosedSignalGroup.RUNTIME -> !runtimeArtifactAvailable || !logcatAvailable
            LSPosedSignalGroup.POLICY -> !dirtyPolicyAvailable
            LSPosedSignalGroup.BINDER -> false
        }
    }

    private fun LSPosedReport.hasPolicySignals(): Boolean {
        return policySignalCount > 0
    }

    private fun LSPosedReport.hasLsposedPolicySignal(): Boolean {
        return signals.any {
            it.group == LSPosedSignalGroup.POLICY &&
                it.label.contains("lsposed", ignoreCase = true)
        }
    }
}
