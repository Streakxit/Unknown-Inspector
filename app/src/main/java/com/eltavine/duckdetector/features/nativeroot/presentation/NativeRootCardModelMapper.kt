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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootDetailRowModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootHeaderFactModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootImpactItemModel

class NativeRootCardModelMapper {

    fun map(
        report: NativeRootReport,
    ): NativeRootCardModel {
        return NativeRootCardModel(
            title = "Root Nativo",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            nativeRows = buildNativeRows(report),
            runtimeRows = buildRuntimeRows(report),
            kernelRows = buildKernelRows(report),
            propertyRows = buildPropertyRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: NativeRootReport): String {
        return when (report.stage) {
            NativeRootStage.LOADING -> "supercall + prctl + setresuid + runtime paths + /proc + isolated mount"
            NativeRootStage.FAILED -> "native root scan failed"
            NativeRootStage.READY -> when {
                !report.nativeAvailable && report.findings.isEmpty() -> "native detector unavailable"
                else -> "${report.pathCheckCount} paths · ${report.processCheckedCount} proc entries · ${report.cgroupPathCheckCount} cgroup dirs · ${report.kernelSourceCount} kernel sources · ${report.propertyCheckCount} props"
            }
        }
    }

    private fun buildVerdict(report: NativeRootReport): String {
        return when (report.stage) {
            NativeRootStage.LOADING -> "Escaneando indicadores root del kernel"
            NativeRootStage.FAILED -> "Escaneo de root nativo fallido"
            NativeRootStage.READY -> when {
                report.kernelSuDetected && report.aPatchDetected -> "Indicadores de KernelSU y APatch detectados"
                report.selfSuDomain -> "La app ya se ejecuta en el dominio su de KernelSU"
                report.kernelSuDetected && report.ksuSupercallProbeHit -> "KernelSU detectado via ksu_driver"
                report.kernelSuDetected && report.prctlProbeHit -> "KernelSU detectado via prctl"
                report.kernelSuDetected -> "Indicadores de KernelSU detectados"
                report.aPatchDetected -> "Indicadores de APatch detectados"
                report.magiskDetected -> "Indicadores nativos de Magisk detectados"
                report.rootDetected -> "Indicadores de root detectados"
                report.hasDangerFindings -> "${report.dangerFindingCount} runtime root signal(s)"
                report.mountAnchorDriftCount > 0 -> "Deriva de montaje aislado sugiere manipulación de namespace"
                report.mountDriftSignalCount > 0 -> "La deriva de namespace del proceso aislado requiere revisión"
                report.ksuManagerPackagePresent && report.ksuManagerTraitHitCount > 0 ->
                    "Fingerprint débil del manager de KernelSU detectado"

                report.ksuManagerPackagePresent -> "KernelSU manager package detected"
                report.hasWarningFindings -> "${report.warningFindingCount} native signal(s) need review"
                !report.nativeAvailable -> "Detector nativo no disponible"
                report.hasReducedCoverage() -> "Escaneo de root nativo con cobertura reducida"
                else -> "Sin indicadores de root nativo"
            }
        }
    }

    private fun buildSummary(report: NativeRootReport): String {
        val base = when (report.stage) {
            NativeRootStage.LOADING ->
                "Las sondas nativas verifican supercall, syscall, side-channel, deriva de montaje y evidencia de propiedades."

            NativeRootStage.FAILED ->
                report.errorMessage ?: "El escaneo de Root Nativo falló antes de recolectar evidencia."

            NativeRootStage.READY -> when {
                report.hasDangerFindings ->
                    "Detecciones de ksu_driver de solo lectura, syscall directos, IOC del proceso propio, rutas del manager root, rutas de residuo de runtime, deriva de metadatos /data/local/tmp, fuga cgroup/proceso, procesos root inesperados o deriva de namespace indican infraestructura root nativa activa."

                report.hasWarningFindings ->
                    "Solo surgieron señales más débiles de deriva de montaje de proceso aislado, fingerprints del manifest del manager o residuos de proceso, cgroup, kernel o metadatos. Son dignas de revisión, pero no tan fuertes como las sondas nativas directas."

                !report.nativeAvailable ->
                    "Este detector depende principalmente de sondas nativas JNI. La cobertura nativa no estuvo disponible en este build, y las verificaciones de runtime restantes permanecieron limpias."

                report.hasReducedCoverage() ->
                    "No native root indicator surfaced from available probes, but one or more direct, cgroup, isolated-process, or package-visibility evidence paths had reduced coverage."

                else ->
                    "Las sondas supercall de KernelSU, prctl, canal lateral KernelPatch, IOC de proceso propio, deriva de montaje aislado, fingerprint del manifest, canal lateral SUSFS, artefactos /data/adb, rutas de residuo curadas, metadatos /data/local/tmp, auditoría de procesos root, fugas cgroup, strings del kernel y propiedades permanecieron limpios."
            }
        }
        if (report.stage != NativeRootStage.READY) {
            return base
        }
        return when {
            report.ksuSupercallBlocked ->
                "$base The read-only ksu_driver probe was blocked by app seccomp on this device, so the verdict falls back to prctl, self-process IOC, path, cgroup, kernel-string, and property evidence."

            !report.ksuSupercallAttempted ->
                "$base The read-only ksu_driver probe was unavailable, so this card relied on the remaining native checks."

            else -> base
        }
    }

    private fun buildHeaderFacts(report: NativeRootReport): List<NativeRootHeaderFactModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderFacts(
                "Pendiente",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            NativeRootStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            NativeRootStage.READY -> listOf(
                NativeRootHeaderFactModel(
                    label = "Flags",
                    value = familyValue(report),
                    status = when {
                        report.detectedFamilies.isEmpty() && report.hasReducedCoverage() -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )
                        report.detectedFamilies.isEmpty() && report.nativeAvailable -> DetectorStatus.allClear()
                        report.detectedFamilies.isEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.danger()
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Direct",
                    value = when {
                        report.directFindings.isNotEmpty() -> report.directFindings.size.toString()
                        report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> "Limitado"
                        else -> "Limpio"
                    },
                    status = when {
                        report.directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                        report.directFindings.isNotEmpty() -> DetectorStatus.warning()
                        report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Kernel",
                    value = when {
                        report.kernelFindings.isNotEmpty() -> report.kernelFindings.size.toString()
                        report.nativeAvailable -> "Limpio"
                        else -> "N/A"
                    },
                    status = when {
                        report.kernelFindings.isNotEmpty() -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootHeaderFactModel(
                    label = "Runtime",
                    value = if (report.runtimeFindings.isEmpty()) {
                        when {
                            !report.nativeAvailable -> "N/A"
                            report.hasRuntimeReducedCoverage() -> "Limitado"
                            report.nativeAvailable -> "Limpio"
                            else -> "N/A"
                        }
                    } else {
                        report.runtimeFindings.size.toString()
                    },
                    status = when {
                        report.runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                        report.runtimeFindings.isNotEmpty() -> DetectorStatus.warning()
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.hasRuntimeReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildNativeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("KSU supercall", "KernelSU prctl", "SUSFS side-channel"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> buildList {
                addAll(report.directFindings.sortedBy { it.label }.map(::findingRow))
                if (report.ksuSupercallBlocked) {
                    add(
                        NativeRootDetailRowModel(
                            label = "KSU supercall",
                            value = "Bloqueado por seccomp",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                            detail = "El proceso helper reboot() sacrificial terminó bajo seccomp antes de poder instalar un fd [ksu_driver] temporal. Otras verificaciones de KernelSU continuaron.",
                        )
                    )
                }
            }
        }
    }

    private fun buildRuntimeRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf(
                    "IOC de proceso propio",
                    "Deriva de montaje aislado",
                    "Fingerprint del manager",
                    "Rutas de runtime",
                    "Procesos root",
                    "Fuga cgroup",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf(
                    "IOC de proceso propio",
                    "Deriva de montaje aislado",
                    "Fingerprint del manager",
                    "Rutas de runtime",
                    "Procesos root",
                    "Fuga cgroup",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> report.runtimeFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildKernelRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("Símbolos del kernel", "Módulos del kernel", "Identidad del kernel"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("Símbolos del kernel", "Módulos del kernel", "Identidad del kernel"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> report.kernelFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildPropertyRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf("Propiedades específicas de root"),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
                monospace = true,
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf("Propiedades específicas de root"),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
                monospace = true,
            )

            NativeRootStage.READY -> report.propertyFindings.sortedBy { it.label }.map(::findingRow)
        }
    }

    private fun buildImpactItems(report: NativeRootReport): List<NativeRootImpactItemModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> listOf(
                NativeRootImpactItemModel(
                    text = "Recolectando evidencia de root nativo local.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            NativeRootStage.FAILED -> listOf(
                NativeRootImpactItemModel(
                    text = report.errorMessage ?: "Escaneo de root nativo fallido.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            NativeRootStage.READY -> buildList {
                if (report.hasDangerFindings) {
                    add(
                        NativeRootImpactItemModel(
                            text = "Direct native hits are stronger than plain package or property signals because they come from syscall behavior, runtime processes, cgroup visibility mismatches, or corroborated runtime residue paths.",
                            status = DetectorStatus.danger(),
                        ),
                    )
                } else if (report.hasWarningFindings) {
                    add(
                        NativeRootImpactItemModel(
                            text = "La deriva de montaje de proceso aislado, fingerprints del manifest del manager, strings del kernel, residuos de propiedades o fugas cgroup pueden indicar historial root nativo, pero son más débiles que las sondas directas a nivel syscall.",
                            status = DetectorStatus.warning(),
                        ),
                    )
                } else if (report.nativeAvailable) {
                    add(
                        if (report.hasReducedCoverage()) {
                            NativeRootImpactItemModel(
                                text = "No se detectó ningún indicador de root nativo, pero una o más rutas de evidencia de soporte no estuvieron disponibles.",
                                status = DetectorStatus.info(InfoKind.SUPPORT),
                            )
                        } else {
                            NativeRootImpactItemModel(
                                text = "No surgieron trazas comunes de KernelSU, APatch, Magisk, SUSFS ni fugas cgroup del conjunto de sondas actual.",
                                status = DetectorStatus.allClear(),
                            )
                        },
                    )
                }
                add(
                    NativeRootImpactItemModel(
                        text = if (report.nativeAvailable) {
                            if (report.hasReducedCoverage()) {
                                "La cobertura reducida disminuye la confianza sin implicar una detección positiva de root."
                            } else {
                                "Un root determinado puede ocultar o eliminar residuos, por lo que la ausencia de detecciones nativas no prueba que el dispositivo sea original."
                            }
                        } else {
                            "La cobertura nativa no estuvo disponible, por lo que esta tarjeta no debe tratarse como un veredicto limpio fuerte."
                        },
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente"
            )

            NativeRootStage.FAILED -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.ERROR),
                "Fallido"
            )

            NativeRootStage.READY -> report.methods.map { result ->
                NativeRootDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: NativeRootReport): List<NativeRootDetailRowModel> {
        return when (report.stage) {
            NativeRootStage.LOADING -> placeholderRows(
                listOf(
                    "Rutas verificadas",
                    "Detecciones de ruta",
                    "Procs verificados",
                    "Procs denegados",
                    "Detecciones de proc",
                    "Self context",
                    "FDs driver propios",
                    "FDs wrapper propios",
                    "NS montaje principal",
                    "NS montaje aislado",
                    "Detecciones deriva montaje",
                    "Derivas de anclaje de montaje",
                    "Manager package",
                    "Rasgos del manager",
                    "Rutas cgroup",
                    "Cgroup visible",
                    "Proc cgroup",
                    "Cgroup denegado",
                    "Detecciones cgroup",
                    "Fuentes del kernel",
                    "Detecciones del kernel",
                    "Propiedades verificadas",
                    "Detecciones de propiedades",
                    "Native library",
                ),
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente",
            )

            NativeRootStage.FAILED -> placeholderRows(
                listOf(
                    "Rutas verificadas",
                    "Detecciones de ruta",
                    "Procs verificados",
                    "Procs denegados",
                    "Detecciones de proc",
                    "Self context",
                    "FDs driver propios",
                    "FDs wrapper propios",
                    "NS montaje principal",
                    "NS montaje aislado",
                    "Detecciones deriva montaje",
                    "Derivas de anclaje de montaje",
                    "Manager package",
                    "Rasgos del manager",
                    "Rutas cgroup",
                    "Cgroup visible",
                    "Proc cgroup",
                    "Cgroup denegado",
                    "Detecciones cgroup",
                    "Fuentes del kernel",
                    "Detecciones del kernel",
                    "Propiedades verificadas",
                    "Detecciones de propiedades",
                    "Native library",
                ),
                DetectorStatus.info(InfoKind.ERROR),
                "Error",
            )

            NativeRootStage.READY -> listOf(
                NativeRootDetailRowModel(
                    "Rutas verificadas",
                    report.pathCheckCount.toString(),
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                NativeRootDetailRowModel(
                    "Detecciones de ruta",
                    report.pathHitCount.toString(),
                    when {
                        report.findings.any {
                            it.group == NativeRootGroup.PATH &&
                                it.severity == NativeRootFindingSeverity.DANGER
                        } -> DetectorStatus.danger()

                        report.findings.any {
                            it.group == NativeRootGroup.PATH &&
                                it.severity == NativeRootFindingSeverity.WARNING
                        } -> DetectorStatus.warning()

                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Procs verificados",
                    if (report.nativeAvailable) report.processCheckedCount.toString() else "N/A",
                    if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Procs denegados",
                    if (report.nativeAvailable) report.processDeniedCount.toString() else "N/A",
                    DetectorStatus.info(InfoKind.SUPPORT),
                ),
                NativeRootDetailRowModel(
                    "Detecciones de proc",
                    if (report.nativeAvailable) report.processHitCount.toString() else "N/A",
                    when {
                        report.processHitCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Self context",
                    when {
                        report.selfContext.isNotBlank() -> report.selfContext
                        report.nativeAvailable -> "No disponible"
                        else -> "N/A"
                    },
                    when {
                        report.selfSuDomain -> DetectorStatus.danger()
                        report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                        report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "FDs driver propios",
                    if (report.nativeAvailable) report.selfKsuDriverFdCount.toString() else "N/A",
                    when {
                        report.selfKsuDriverFdCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "FDs wrapper propios",
                    if (report.nativeAvailable) report.selfKsuFdwrapperFdCount.toString() else "N/A",
                    when {
                        report.selfKsuFdwrapperFdCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "NS montaje principal",
                    report.mainMountNamespaceInode.ifBlank { "No disponible" },
                    when {
                        report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                        report.mainMountNamespaceInode.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "NS montaje aislado",
                    when {
                        report.isolatedMountNamespaceInode.isNotBlank() -> report.isolatedMountNamespaceInode
                        report.isolatedMountProbeAvailable -> "No disponible"
                        else -> "N/A"
                    },
                    when {
                        report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                        report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Detecciones deriva montaje",
                    if (report.isolatedMountProbeAvailable) report.mountDriftSignalCount.toString() else "N/A",
                    when {
                        report.mountDriftSignalCount > 0 -> DetectorStatus.warning()
                        report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Derivas de anclaje de montaje",
                    if (report.isolatedMountProbeAvailable) report.mountAnchorDriftCount.toString() else "N/A",
                    when {
                        report.mountAnchorDriftCount > 0 -> DetectorStatus.warning()
                        report.isolatedMountProbeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Manager package",
                    when {
                        report.ksuManagerPackagePresent -> "Presente"
                        report.ksuManagerVisibilityRestricted -> "Scoped"
                        else -> "Limpio"
                    },
                    when {
                        report.ksuManagerPackagePresent -> DetectorStatus.warning()
                        report.ksuManagerVisibilityRestricted -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                NativeRootDetailRowModel(
                    "Rasgos del manager",
                    when {
                        report.ksuManagerPackagePresent -> "${report.ksuManagerTraitHitCount}/3"
                        report.ksuManagerVisibilityRestricted -> "N/A"
                        else -> "N/A"
                    },
                    when {
                        report.ksuManagerPackagePresent -> DetectorStatus.warning()
                        report.ksuManagerVisibilityRestricted -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                NativeRootDetailRowModel(
                    "Rutas cgroup",
                    if (report.cgroupAvailable) report.cgroupPathCheckCount.toString() else "N/A",
                    if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Cgroup visible",
                    if (report.cgroupAvailable) report.cgroupAccessiblePathCount.toString() else "N/A",
                    if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Proc cgroup",
                    if (report.cgroupAvailable) report.cgroupProcessCheckedCount.toString() else "N/A",
                    if (report.cgroupAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Cgroup denegado",
                    if (report.cgroupAvailable) report.cgroupProcDeniedCount.toString() else "N/A",
                    DetectorStatus.info(InfoKind.SUPPORT),
                ),
                NativeRootDetailRowModel(
                    "Detecciones cgroup",
                    if (report.cgroupAvailable) report.cgroupHitCount.toString() else "N/A",
                    when {
                        report.cgroupFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                        report.cgroupHitCount > 0 -> DetectorStatus.warning()
                        report.cgroupAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Fuentes del kernel",
                    if (report.nativeAvailable) report.kernelSourceCount.toString() else "N/A",
                    if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Detecciones del kernel",
                    if (report.nativeAvailable) report.kernelHitCount.toString() else "N/A",
                    when {
                        report.kernelHitCount > 0 -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Propiedades verificadas",
                    if (report.nativeAvailable) report.propertyCheckCount.toString() else "N/A",
                    if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
                NativeRootDetailRowModel(
                    "Detecciones de propiedades",
                    if (report.nativeAvailable) report.propertyHitCount.toString() else "N/A",
                    when {
                        report.propertyHitCount > 0 -> DetectorStatus.warning()
                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                NativeRootDetailRowModel(
                    "Native library",
                    if (report.nativeAvailable) "Loaded" else "No disponible",
                    if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun findingRow(finding: NativeRootFinding): NativeRootDetailRowModel {
        return NativeRootDetailRowModel(
            label = finding.label,
            value = finding.value,
            status = findingStatus(finding),
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<NativeRootHeaderFactModel> {
        return listOf(
            NativeRootHeaderFactModel("Flags", value, status),
            NativeRootHeaderFactModel("Direct", value, status),
            NativeRootHeaderFactModel("Kernel", value, status),
            NativeRootHeaderFactModel("Runtime", value, status),
        )
    }

    private fun placeholderRows(
        labels: List<String>,
        status: DetectorStatus,
        value: String,
        monospace: Boolean = false,
    ): List<NativeRootDetailRowModel> {
        return labels.map { label ->
            NativeRootDetailRowModel(
                label = label,
                value = value,
                status = status,
                detailMonospace = monospace,
            )
        }
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<NativeRootDetailRowModel> {
        return listOf(
            "ksuReadonlySupercall",
            "prctlProbe",
            "susfsSideChannel",
            "selfProcessIoc",
            "isolatedMountDrift",
            "ksuManagerFingerprint",
            "runtimeArtifacts",
            "cgroupLeakage",
            "kernelTraces",
            "propertyResidue",
            "nativeLibrary",
            "signalSummary",
        ).map { label ->
            NativeRootDetailRowModel(
                label = label,
                value = value,
                status = status,
            )
        }
    }

    private fun familyValue(report: NativeRootReport): String {
        return when {
            report.detectedFamilies.isEmpty() && report.nativeAvailable -> "Ninguno"
            report.detectedFamilies.isEmpty() -> "N/A"
            report.detectedFamilies.size <= 2 -> report.detectedFamilies.joinToString("/")
            else -> report.detectedFamilies.take(2)
                .joinToString("/") + " +${report.detectedFamilies.size - 2}"
        }
    }

    private fun findingStatus(finding: NativeRootFinding): DetectorStatus {
        return when (finding.severity) {
            NativeRootFindingSeverity.DANGER -> DetectorStatus.danger()
            NativeRootFindingSeverity.WARNING -> DetectorStatus.warning()
            NativeRootFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: NativeRootMethodResult): DetectorStatus {
        return when (result.outcome) {
            NativeRootMethodOutcome.CLEAN -> DetectorStatus.allClear()
            NativeRootMethodOutcome.DETECTED -> DetectorStatus.danger()
            NativeRootMethodOutcome.WARNING -> DetectorStatus.warning()
            NativeRootMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun NativeRootReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            NativeRootStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            NativeRootStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            NativeRootStage.READY -> when {
                hasDangerFindings -> DetectorStatus.danger()
                hasWarningFindings -> DetectorStatus.warning()
                !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }

    private fun NativeRootReport.hasReducedCoverage(): Boolean {
        return ksuSupercallBlocked ||
                !ksuSupercallAttempted ||
                hasRuntimeReducedCoverage()
    }

    private fun NativeRootReport.hasRuntimeReducedCoverage(): Boolean {
        return !cgroupAvailable ||
                !isolatedMountProbeAvailable ||
                ksuManagerVisibilityRestricted
    }
}
