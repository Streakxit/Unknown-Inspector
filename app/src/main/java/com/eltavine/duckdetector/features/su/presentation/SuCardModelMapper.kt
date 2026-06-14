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

package com.eltavine.duckdetector.features.su.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.su.domain.SuMethodOutcome
import com.eltavine.duckdetector.features.su.domain.SuMethodResult
import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.domain.SuStage
import com.eltavine.duckdetector.features.su.ui.model.SuCardModel
import com.eltavine.duckdetector.features.su.ui.model.SuDetailRowModel
import com.eltavine.duckdetector.features.su.ui.model.SuHeaderFactModel
import com.eltavine.duckdetector.features.su.ui.model.SuImpactItemModel

class SuCardModelMapper {

    fun map(
        report: SuReport,
    ): SuCardModel {
        return SuCardModel(
            title = "SU",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            artifactRows = buildArtifactRows(report),
            contextRows = buildContextRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING -> "rutas su + PATH + daemons adb + contexto nativo"
            SuStage.FAILED -> "sonda root local fallida"
            SuStage.READY -> buildString {
                append("${report.checkedSuPathCount} rutas su")
                append(" · ${report.checkedDaemonPathCount} rutas de daemon adb")
                append(
                    if (report.nativeAvailable) {
                        " · escaneo nativo /proc"
                    } else {
                        " · contexto propio de respaldo"
                    },
                )
            }
        }
    }

    private fun buildVerdict(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING -> "Escaneando artefactos root"
            SuStage.FAILED -> "Escaneo SU fallido"
            SuStage.READY -> when {
                report.daemons.isNotEmpty() -> "${daemonNames(report)} daemon detectado"
                report.selfContextAbnormal || report.suspiciousProcesses.isNotEmpty() -> "Contexto root anormal detectado"
                report.suBinaries.isNotEmpty() -> "Binario SU detectado"
                !report.nativeAvailable -> "Sin indicadores root en sondas disponibles"
                else -> "Sin indicadores root"
            }
        }
    }

    private fun buildSummary(report: SuReport): String {
        return when (report.stage) {
            SuStage.LOADING ->
                "Las sondas de archivo, PATH, daemon adb, contexto SELinux y visibilidad /proc están recolectando evidencia local."

            SuStage.FAILED ->
                report.errorMessage ?: "Escaneo SU fallido before root evidence could be assembled."

            SuStage.READY -> when {
                report.daemons.isNotEmpty() ->
                    "${daemonNames(report)} huellas encontradas en /data/adb, señal directa de gestión root."

                report.selfContextAbnormal || report.suspiciousProcesses.isNotEmpty() ->
                    "Las sondas SELinux detectaron etiquetas anormales o residuos de contexto similares a root."

                report.suBinaries.isNotEmpty() ->
                    "Se encontraron binarios su en ubicaciones del sistema o gestionadas por adb."

                !report.nativeAvailable ->
                    "Las sondas de archivo y daemon estuvieron limpias, pero la enumeración /proc con JNI no estuvo disponible."

                else ->
                    "Binarios su, daemons adb y sondas SELinux nativas permanecieron limpios."
            }
        }
    }

    private fun buildHeaderFacts(report: SuReport): List<SuHeaderFactModel> {
        return when (report.stage) {
            SuStage.LOADING -> placeholderFacts(
                value = "Pendiente",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            )

            SuStage.FAILED -> listOf(
                SuHeaderFactModel("Artefactos", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Daemons", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Contexto", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuHeaderFactModel("Procesos", "N/A", DetectorStatus.info(InfoKind.SUPPORT)),
            )

            SuStage.READY -> listOf(
                SuHeaderFactModel(
                    label = "Artefactos",
                    value = if (report.suBinaries.isEmpty()) "Ninguno" else report.suBinaries.size.toString(),
                    status = if (report.suBinaries.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                SuHeaderFactModel(
                    label = "Daemons",
                    value = if (report.daemons.isEmpty()) "Ninguno" else daemonNames(report),
                    status = if (report.daemons.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                ),
                SuHeaderFactModel(
                    label = "Contexto",
                    value = when {
                        report.selfContextAbnormal -> "Anormal"
                        report.selfContext.isNotBlank() -> "Normal"
                        else -> "Desconocido"
                    },
                    status = when {
                        report.selfContextAbnormal -> DetectorStatus.danger()
                        report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                SuHeaderFactModel(
                    label = "Procesos",
                    value = when {
                        !report.nativeAvailable -> "N/A"
                        report.suspiciousProcesses.isEmpty() -> "0"
                        else -> report.suspiciousProcesses.size.toString()
                    },
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.suspiciousProcesses.isEmpty() -> DetectorStatus.allClear()
                        else -> DetectorStatus.danger()
                    },
                ),
            )
        }
    }

    private fun buildArtifactRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    label = "Daemons root",
                    value = "Pendiente",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Binarios SU",
                    value = "Pendiente",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel(
                    label = "Daemons root",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "Binarios SU",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "Daemons root",
                    value = if (report.daemons.isEmpty()) "Ninguno" else daemonNames(report),
                    status = if (report.daemons.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                    detail = report.daemons
                        .joinToString(separator = "\n") { finding -> "${finding.name}: ${finding.path}" }
                        .ifBlank { null },
                    detailMonospace = true,
                ),
                SuDetailRowModel(
                    label = "Binarios SU",
                    value = if (report.suBinaries.isEmpty()) "Ninguno" else report.suBinaries.size.toString(),
                    status = if (report.suBinaries.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                    detail = report.suBinaries.joinToString(separator = "\n").ifBlank { null },
                    detailMonospace = true,
                ),
            )
        }
    }

    private fun buildContextRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    label = "Contexto propio",
                    value = "Pendiente",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Procesos sospechosos",
                    value = "Pendiente",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Ruta de sonda",
                    value = "Cargando",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel(
                    label = "Contexto propio",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "Procesos sospechosos",
                    value = "Error",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
                SuDetailRowModel(
                    label = "Ruta de sonda",
                    value = "No disponible",
                    status = DetectorStatus.info(InfoKind.ERROR),
                    detail = report.errorMessage,
                ),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "Contexto propio",
                    value = when {
                        report.selfContextAbnormal -> "Anormal"
                        report.selfContext.isNotBlank() -> "Normal"
                        else -> "Desconocido"
                    },
                    status = when {
                        report.selfContextAbnormal -> DetectorStatus.danger()
                        report.selfContext.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = report.selfContext.ifBlank {
                        "No se pudo leer el contexto SELinux del proceso de app actual."
                    },
                    detailMonospace = report.selfContext.isNotBlank(),
                ),
                SuDetailRowModel(
                    label = "Procesos sospechosos",
                    value = when {
                        !report.nativeAvailable -> "No disponible"
                        report.suspiciousProcesses.isEmpty() -> "Ninguno"
                        else -> report.suspiciousProcesses.size.toString()
                    },
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.suspiciousProcesses.isEmpty() -> DetectorStatus.allClear()
                        else -> DetectorStatus.danger()
                    },
                    detail = report.suspiciousProcesses.joinToString(separator = "\n").ifBlank {
                        if (report.nativeAvailable) {
                            "Ningún contexto de proceso coincidió con tokens de root."
                        } else {
                            "La enumeración nativa de procesos /proc no está disponible en este build."
                        }
                    },
                    detailMonospace = true,
                ),
                SuDetailRowModel(
                    label = "Ruta de sonda",
                    value = when {
                        report.nativeAvailable -> "Escaneo JNI syscall"
                        report.selfContext.isNotBlank() -> "Lectura de respaldo"
                        else -> "No disponible"
                    },
                    status = when {
                        report.nativeAvailable -> DetectorStatus.allClear()
                        report.selfContext.isNotBlank() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.info(InfoKind.ERROR)
                    },
                    detail = if (report.nativeAvailable) {
                        "Se verificaron ${report.checkedProcessCount} contextos de proceso; ${report.deniedProcessCount} lecturas /proc denegadas. Las lecturas denegadas son evidencia de soporte, no prueba directa de root."
                    } else {
                        "La librería nativa no estuvo disponible, solo se ejecutó el fallback /proc/self/attr/current."
                    },
                ),
            )
        }
    }

    private fun buildImpactItems(report: SuReport): List<SuImpactItemModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuImpactItemModel(
                    text = "Recolectando evidencia root local.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SuStage.FAILED -> listOf(
                SuImpactItemModel(
                    text = report.errorMessage ?: "Escaneo SU fallido.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            SuStage.READY -> when {
                report.hasRootIndicators -> listOf(
                    SuImpactItemModel(
                        text = "Herramientas de escalación de privilegios presentes o visibles desde este contexto.",
                        status = DetectorStatus.danger(),
                    ),
                    SuImpactItemModel(
                        text = "Los gestores root pueden ocultar archivos, alterar el sistema y debilitar señales de confianza.",
                        status = DetectorStatus.danger(),
                    ),
                    SuImpactItemModel(
                        text = "Apps bancarias, de pago, DRM y sensibles a integridad pueden negarse a ejecutarse.",
                        status = DetectorStatus.danger(),
                    ),
                )

                report.nativeAvailable -> listOf(
                    SuImpactItemModel(
                        text = "No se encontraron binarios SU comunes ni daemons root adb.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "Las sondas nativas de contexto SELinux se mantuvieron dentro de los límites normales.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "Esto es evidencia heurística, no prueba de un dispositivo sin modificar.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                else -> listOf(
                    SuImpactItemModel(
                        text = "Las sondas de archivo y daemon adb estuvieron limpias.",
                        status = DetectorStatus.allClear(),
                    ),
                    SuImpactItemModel(
                        text = "La cobertura nativa de contexto /proc no estuvo disponible.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    SuImpactItemModel(
                        text = "La ausencia de artefactos SU no prueba que root sea imposible.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }

    private fun buildMethodRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> placeholderMethodRows(
                DetectorStatus.info(InfoKind.SUPPORT),
                "Pendiente"
            )

            SuStage.FAILED -> placeholderMethodRows(DetectorStatus.info(InfoKind.ERROR), "Fallido")
            SuStage.READY -> report.methods.map { result ->
                SuDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun buildScanRows(report: SuReport): List<SuDetailRowModel> {
        return when (report.stage) {
            SuStage.LOADING -> listOf(
                SuDetailRowModel(
                    "Rutas SU verificadas",
                    "Pendiente",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Rutas de daemon verificadas",
                    "Pendiente",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Contextos proc verificados",
                    "Pendiente",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel(
                    "Lecturas proc denegadas",
                    "Pendiente",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
            )

            SuStage.FAILED -> listOf(
                SuDetailRowModel("Rutas SU verificadas", "Error", DetectorStatus.info(InfoKind.ERROR)),
                SuDetailRowModel(
                    "Rutas de daemon verificadas",
                    "Error",
                    DetectorStatus.info(InfoKind.ERROR)
                ),
                SuDetailRowModel(
                    "Contextos proc verificados",
                    "N/A",
                    DetectorStatus.info(InfoKind.SUPPORT)
                ),
                SuDetailRowModel("Lecturas proc denegadas", "N/A", DetectorStatus.info(InfoKind.SUPPORT)),
            )

            SuStage.READY -> listOf(
                SuDetailRowModel(
                    label = "Rutas SU verificadas",
                    value = report.checkedSuPathCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Rutas de daemon verificadas",
                    value = report.checkedDaemonPathCount.toString(),
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                SuDetailRowModel(
                    label = "Contextos proc verificados",
                    value = if (report.nativeAvailable) report.checkedProcessCount.toString() else "N/A",
                    status = when {
                        !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.checkedProcessCount > 0 -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                SuDetailRowModel(
                    label = "Lecturas proc denegadas",
                    value = if (report.nativeAvailable) report.deniedProcessCount.toString() else "N/A",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<SuHeaderFactModel> {
        return listOf(
            SuHeaderFactModel("Artefactos", value, status),
            SuHeaderFactModel("Daemons", value, status),
            SuHeaderFactModel("Contexto", value, status),
            SuHeaderFactModel("Procesos", value, status),
        )
    }

    private fun placeholderMethodRows(
        status: DetectorStatus,
        value: String,
    ): List<SuDetailRowModel> {
        return listOf(
            SuDetailRowModel("daemonScan", value, status),
            SuDetailRowModel("fileScan", value, status),
            SuDetailRowModel("nativeSyscall", value, status),
            SuDetailRowModel("nativeLibrary", value, status),
        )
    }

    private fun daemonNames(report: SuReport): String {
        val names = report.daemons.map { it.name }.distinct()
        return when {
            names.isEmpty() -> "Ninguno"
            names.size <= 2 -> names.joinToString("/")
            else -> names.take(2).joinToString("/") + " +${names.size - 2}"
        }
    }

    private fun methodStatus(result: SuMethodResult): DetectorStatus {
        return when (result.outcome) {
            SuMethodOutcome.CLEAN -> DetectorStatus.allClear()
            SuMethodOutcome.DETECTED -> DetectorStatus.danger()
            SuMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun SuReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            SuStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            SuStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            SuStage.READY -> when {
                hasRootIndicators -> DetectorStatus.danger()
                !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.allClear()
            }
        }
    }
}
