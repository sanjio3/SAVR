<template>
  <section v-if="store.selectedTask" ref="dashboardRoot" class="page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="hero">
      <div class="row between wrap gap-md">
        <div class="stack">
          <h1>{{ store.selectedTask.name }}</h1>
          <p class="muted">{{ store.selectedTask.output_dir }}</p>
        </div>
        <div class="row wrap gap-sm">
          <span class="badge">{{ taskBadge(store.selectedTask) }}</span>
        </div>
      </div>

      <!-- A4（2026-09-18，方案二）：运行期顶部计数器改口径。
           根因：findings 表由任务收尾的 replace_for_task 统一重写（replace 语义），运行期间本任务
           在该表零行，而下方统计读的正是 store.findings —— 顶部计数器在整轮运行里恒为 0，
           与同页阶段卡片（SCA 348 / A1 90 / A2 157 / D2 已证可利用）自相矛盾。
           现改为运行期只显示可直读的分轴计数、不做加总，并显式标注「运行中」，收尾后切回完整口径。 -->
      <div v-if="isTaskRunning" class="stats-grid task-summary-grid compact">
        <div class="stat-card">
          <span class="muted">SCA（库层）</span>
          <strong class="num">{{ stageMetric("sca", "finding_count") }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">A1 规则</span>
          <strong class="num">{{ pipelineMetric("a1", "finding_count") }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">A2 语义（未去重）</span>
          <strong class="num">{{ pipelineMetric("a2", "finding_count") }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">D2 已证可利用</span>
          <strong class="num">{{ stageMetric("d2", "exploitable_count") }}</strong>
        </div>
      </div>
      <p v-if="isTaskRunning" class="muted running-counter-hint">
        运行中 · 以上为各阶段独立计数，不做加总：A1 与 A2 的 finding 存在重叠、SCA 属库层与应用层不同轴。
        应用层合计与占比在收尾后按 canonical 口径给出。
      </p>

      <div v-if="!isTaskRunning" class="stats-grid task-summary-grid compact">
        <div class="stat-card">
          <span class="muted">应用层漏洞</span>
          <strong class="num">{{ appLayerCount }}</strong>
          <!-- 2026-09-18（A2 方案二）：聚合吸收成员已有独立 findings 行（用于覆盖率统计与关联桥），
               但它们是所属聚合发现的构成节点、不是独立漏洞，故不计入「应用层漏洞」，
               在此单独披露条数，避免同一 sink 被双计。 -->
          <span v-if="absorbedFindings.length" class="muted stat-note">
            另 {{ absorbedFindings.length }} 条为聚合成员（已计入所属聚合项）
          </span>
        </div>
        <div class="stat-card">
          <span class="muted">SCA 组件漏洞</span>
          <strong class="num">{{ scaFindings.length }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">D2 可利用</span>
          <strong class="num">{{ stageMetric("d2", "exploitable_count") }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">报告份数</span>
          <strong class="num">{{ store.reports.length }}</strong>
        </div>
        <div class="stat-card">
          <span class="muted">合计漏洞</span>
          <strong class="num">{{ totalFindings }}</strong>
        </div>
      </div>

      <!-- D4：占比条。五个数字卡等宽，比例关系全靠减法看不出来，这里补上可视化。
           SCA 常常是缺口的大头（实测 java-sec-code：348/579 = 60%），不显式画出来容易被误读。 -->
      <div v-if="!isTaskRunning && totalFindings > 0" class="stack gap-xs" style="margin-top: 14px">
        <div class="share-bar" role="img" :aria-label="`应用层漏洞 ${appLayerCount} 条，SCA 组件漏洞 ${scaFindings.length} 条`">
          <div class="share-seg app" :style="{ width: appSharePct + '%' }" :title="`应用层漏洞 ${appLayerCount} 条（${appSharePct}%）`" />
          <div class="share-seg sca" :style="{ width: 100 - appSharePct + '%' }" :title="`SCA 组件漏洞 ${scaFindings.length} 条（${100 - appSharePct}%）`" />
        </div>
        <div class="share-legend">
          <span><i class="swatch app" />应用层漏洞 {{ appLayerCount }} 条 · {{ appSharePct }}%</span>
          <span><i class="swatch sca" />SCA 组件漏洞 {{ scaFindings.length }} 条 · {{ 100 - appSharePct }}%</span>
          <span>合计 {{ totalFindings }} 条<template v-if="absorbedFindings.length">（含 {{ absorbedFindings.length }} 条聚合成员）</template></span>
        </div>
      </div>
    </div>

    <div class="row wrap gap-sm">
      <button
        v-for="tab in taskTabs"
        :key="tab"
        type="button"
        class="ghost-button"
        :class="{ active: selectedTab === tab }"
        @click="selectedTab = tab"
      >
        {{ tabLabel(tab) }}
      </button>
    </div>

    <section v-if="selectedTab === 'Overview'" class="stack">
      <!-- 批次 2（2026-09-22）：横向流程条 → 纵向步骤流。
           原横向条把 10 个阶段压成一排等宽格子，窄屏必须缩写，且每格一个实心色圆点；
           现在一步一行：方向与阅读方向一致，阶段码由小圆环承担、名称只剩裸名（修掉「A1 A1 …」）。
           批次 4（2026-09-22）：结构抽到 components/StepFlow.vue，本页只负责把阶段映射成展示项。
           组件侧 emit 的是 string（它不该知道本项目的阶段键联合类型），故在此收窄回 TaskStageKey。 -->
      <StepFlow :items="stepItems" @select="(key) => selectStage(key as TaskStageKey)" />

      <!-- 总览永久隐藏「非有效」发现（SCA 已修复/不受影响、A1/A2 误报·无证据），缓解数字墙。 -->
      <div
        v-if="activeStageValue && ['sca', 'a1', 'a2'].includes(activeStageValue.key)"
        class="overview-filterbar row between wrap gap-sm"
      >
        <span class="muted small">已默认隐藏 SCA 已修复/不受影响、A1/A2 误报·无证据</span>
        <span class="muted small" v-if="activeStageValue.key === 'sca'">
          已隐藏 {{ scaNotAffectedCount }} 条「已修复/不受影响」
        </span>
      </div>

      <!-- 2.1 合并（待请示批准）：原常驻 stage-task-list 块已删除——它的头部（阶段码/名称/状态）
           与上方流程条 100% 重复，且自带一套平行的展开导航，观感就是「横条 + 下面又列一遍」。
           任务清单能力已并入下方 stage-detail 卡片：流程条即目录，点谁看谁。 -->

      <section v-if="activeStageValue" class="card stack stage-detail">
        <div class="stage-detail-header">
          <div class="row gap-sm">
            <span class="stage-detail-code">{{ stageCode(activeStageValue.key) }}</span>
            <div>
              <h3>{{ activeStageValue.label }}</h3>
              <p class="muted">{{ stageStatusLabel(activeStageValue.status) }} · {{ stageHint(activeStageValue.key) }}</p>
            </div>
          </div>
          <!-- 2.2 监控化：阶段已耗时 + D1 预计剩余（按本轮已结束阶段的耗时均值估算）。
               无估算依据时不显示，不给假承诺。 -->
          <div class="row wrap gap-xs stage-detail-timing">
            <span class="timing-pill">已耗时 {{ stageElapsedLabel(activeStageValue) }}</span>
            <span v-if="stageEtaLabel(activeStageValue)" class="timing-pill is-estimate">
              预计剩余 {{ stageEtaLabel(activeStageValue) }}（估算）
            </span>
          </div>
        </div>

        <p class="stage-detail-summary">{{ activeStageDetail }}</p>

        <!-- 2.1：任务清单并入本卡片（原常驻 stage-task-list 已删）。数据源与裁剪规则不变，
             仍由后端 src/core/pipeline_view.py 提供 total / items。 -->
        <div class="stage-detail-tasks">
          <h4>
            任务清单
            <span class="muted"> · {{ stageTaskTotal(activeStageValue) }} 个任务</span>
          </h4>
          <ul class="stage-task-items">
            <li v-for="(it, i) in stageTaskItems(activeStageValue)" :key="`detail-${activeStageValue.key}-${i}`" class="stage-task-item">
              <span class="task-dot" :class="`dot-${it.status || 'pending'}`" />
              <span class="task-name">{{ it.name || "—" }}</span>
              <span class="task-detail">{{ it.detail || "" }}</span>
            </li>
            <li v-if="!stageTaskItems(activeStageValue).length" class="stage-task-item muted">该阶段暂无明细任务</li>
            <li v-if="stageTaskTotal(activeStageValue) > stageTaskItems(activeStageValue).length" class="stage-task-item muted">
              共 {{ stageTaskTotal(activeStageValue) }} 条，显示前 {{ stageTaskItems(activeStageValue).length }} 条（全量会撑大每秒推送的进度事件）
            </li>
          </ul>
        </div>

        <!-- 通用指标条：D2 已有独立中文子面板（已验证/可利用/已验证POC），避免中英双显冗余 -->
        <div v-if="metricEntries(activeStageValue.metrics).length && activeStageValue.key !== 'd2'" class="stage-metrics">
          <div v-for="[key, value] in metricEntries(activeStageValue.metrics)" :key="key" class="metric-pill">
            <span class="muted">{{ humanizeKey(key) }}</span>
            <strong>{{ fmtVal(value) }}</strong>
          </div>
        </div>

        <!-- A0: 入口发现子面板 -->
        <div v-if="activeStageValue.key === 'preprocess'" class="stage-subpanel">
          <h4>入口发现</h4>
          <p class="muted">{{ stageSummary("entry_discovery") }}</p>
          <div class="stage-metrics">
            <div class="metric-pill"><span class="muted">Entries</span><strong>{{ entryCount }}</strong></div>
            <div class="metric-pill"><span class="muted">Rule candidates</span><strong>{{ entryRuleCount }}</strong></div>
          </div>
        </div>

        <!-- SCA -->
        <div v-if="activeStageValue.key === 'sca'" class="stage-subpanel">
          <h4>SCA findings</h4>
          <p class="muted">「版本核查」比对 advisory 的 fixed 版本与组件实际版本：实际版本 ≥ fixed 版本即判定已修复/不受影响（疑似误报）。「交叉验证」标记同一 advisory 是否被 ≥2 个不同扫描器共同报出。</p>
          <template v-if="scaFindings.length">
            <!-- Q1：并/交集双视图，用户自取信哪种数据 -->
            <div class="sca-view-toggle row wrap gap-sm">
              <button type="button" class="ghost-button tiny" :class="{ active: scaView === 'union' }" @click="scaView = 'union'">
                并集（osv 检测全量）· {{ scaUnionCount }}
              </button>
              <button type="button" class="ghost-button tiny" :class="{ active: scaView === 'double' }" @click="scaView = 'double'">
                双重检测（交集·高置信）· {{ scaIntersectionCount }}
              </button>
            </div>
            <p class="muted sca-view-hint">
              <template v-if="scaView === 'union'">并集覆盖全部唯一组件漏洞（保召回，含仅单工具报出的 {{ scaSingleToolCount }} 条）。同一组件漏洞在双重检测中只计一次（已按 CVE 别名去重）。</template>
              <template v-else>交集仅展示被 ≥2 个不同扫描器共同报出、确认一致的 {{ scaIntersectionCount }} 条高置信漏洞，误报更低，但可能漏掉单工具才发现的漏洞。</template>
            </p>
            <!-- Q7 去密：「并集（全量）」与「双重检测（交集）」两个数字已显示在上方切换按钮上，
                 此处原样再画一遍 pill 属同屏重复；已移除。保留的三个是切换按钮与提示文案里
                 都没有的独立口径（单工具检测 / 已修复·不受影响 / 未核查）。 -->
            <div class="stage-metrics">
              <div class="metric-pill"><span class="muted">单工具检测</span><strong>{{ scaSingleToolCount }}</strong></div>
              <div class="metric-pill"><span class="muted">已修复/不受影响</span><strong>{{ scaNotAffectedCount }}</strong></div>
              <div class="metric-pill"><span class="muted">未核查</span><strong>{{ scaUncheckedCount }}</strong></div>
            </div>
            <div class="table-wrap cols-7">
            <table>
              <thead><tr><th>Component</th><th>Vulnerability</th><th>Severity</th><th>检测来源</th><th>版本核查</th><th>交叉验证</th><th>Fix</th></tr></thead>
              <tbody>
                <tr v-for="finding in overviewScaRows" :key="finding.id">
                  <td>{{ String(finding.sca_component || finding.raw?.sca?.component_name || '-') }} {{ String(finding.raw?.sca?.component_version || '') }}</td>
                  <td>{{ String(finding.sca_advisory_id || finding.raw?.sca?.vulnerability_id || finding.title) }}</td>
                  <td><SeverityBadge :level="finding.severity" /></td>
                  <td>
                    <span class="badge" :class="scaDetectionTone(finding)" :title="scaDetectionLabel(finding)">{{ scaDetectionLabel(finding) }}</span>
                  </td>
                  <td>
                    <span class="badge" :class="scaVersionBadge(finding).tone" :title="scaVersionBadge(finding).detail">{{ scaVersionBadge(finding).label }}</span>
                  </td>
                  <td>
                    <span class="badge" :class="scaCrossBadge(finding).tone" :title="scaCrossBadge(finding).detail">{{ scaCrossBadge(finding).label }}</span>
                    <div class="muted">{{ scaConfidenceText(finding) }}</div>
                  </td>
                  <td>{{ scaFixText(finding) }}</td>
                </tr>
              </tbody>
            </table>
            </div>
            <!-- Q7 去密：默认只渲染前 20 行，其余按需展开（避免一屏几百行的数字墙）。 -->
            <div v-if="overviewScaFindings.length > OVERVIEW_ROW_LIMIT" class="row gap-sm wrap">
              <button type="button" class="ghost-button tiny" @click="overviewRowsExpanded = !overviewRowsExpanded">
                {{ overviewRowsExpanded ? "收起" : `展开全部 ${overviewScaFindings.length} 条` }}
              </button>
              <span class="muted small">当前显示 {{ overviewScaRows.length }} / {{ overviewScaFindings.length }} 条</span>
            </div>
            <div v-if="scaView === 'double' && !overviewScaFindings.length" class="muted">当前任务没有「双重检测」命中的组件漏洞（所有 SCA 发现均仅由单一扫描器报出）。</div>
          </template>
          <div v-else class="muted">当前任务没有 SCA finding。</div>
        </div>

        <!-- A1/A2 -->
        <div v-if="['a1', 'a2'].includes(activeStageValue.key)" class="stage-subpanel">
          <h4>{{ activeStageValue.key.toUpperCase() }} findings（{{ overviewStageFindings.length }} 条<template v-if="activeStageValue.key === 'a1' && a1GroupRows.length">，聚合为 {{ a1GroupRows.length }} 组</template>）</h4>
          <label class="muted"><input type="checkbox" v-model="showScaFindings" /> 显示 SCA 组件漏洞（{{ scaFindings.length }} 条，默认不计入应用层 findings）</label>
          <label v-if="absorbedFindings.length" class="muted"><input type="checkbox" v-model="showAbsorbedFindings" /> 显示聚合吸收成员（{{ absorbedFindings.length }} 条，默认折叠，避免与所属聚合发现重复）</label>
          <p v-if="activeStageValue.key === 'a1'" class="muted a1-group-note">已按「规则 + 文件」聚合去重展示（A1 为规则模式命中，同一文件内常出现大量同规则重复命中，默认合并为一组）。</p>
          <p v-if="activeStageValue.key === 'a1' && hasBusinessLogicFindings" class="muted bl-continuity-note">
            带「业务逻辑 / 越权」徽章的发现是 A1 一级 family findings（BOLA / 状态机 / 计算逻辑 / 会话认证 / 滥用 DoS 等），与技术漏洞共用同一组流水线卡片，并在 D 阶段经「双账户差分重放」统一验证，视觉上连续、不另起面板。
          </p>
          <p v-if="activeStageValue.key === 'a2'" class="muted">
            A2 语义分析产出漏洞假说；命中可重放入口的假说会生成 TriggerSpec 并交给 D1 自动重放，最终 PoC 在 D2 校验阶段落地。下表「AI 分析」展示模型推导的入口→危险函数链路，「TriggerSpec」展示是否已生成可重放探针。
          </p>
          <div v-if="activeStageValue.key === 'a2' && closedLoop.mx > 0" class="stack gap-xs">
            <div class="row between wrap gap-sm">
              <span class="muted">闭环重跑进度</span>
              <span class="num">闭环第 {{ closedLoop.it }}/{{ closedLoop.mx }} 轮</span>
            </div>
            <div class="progress tone-ok" role="progressbar" :aria-valuenow="closedLoop.pct" aria-valuemin="0" aria-valuemax="100">
              <span :style="{ width: closedLoop.pct + '%' }" />
            </div>
          </div>
          <!-- A1 聚合视图：一组一行，避免同规则同文件刷屏 -->
          <div v-if="activeStageValue.key === 'a1' && a1Grouped && a1GroupRows.length" class="table-wrap cols-6">
          <table>
            <thead><tr><th>规则</th><th>严重度</th><th>可达性 / 确认态</th><th>文件</th><th>命中行</th><th>规则说明</th></tr></thead>
            <tbody>
              <template v-for="g in a1GroupRows" :key="g.key">
                <tr>
                  <td>
                    <span v-if="isBusinessLogic(g.representative)" class="badge badge-info">{{ businessLogicLabel(g.representative) }}</span>
                    <strong>{{ g.rule }}</strong>
                    <div v-if="g.count > 1" class="muted">同组 × {{ g.count }} 次命中</div>
                  </td>
                  <td>
                    <SeverityBadge :level="g.severity" />
                    <div
                      v-if="severityDowngraded(g.representative)"
                      class="muted"
                      :title="`LLM 原始声称 ${(g.representative.raw as any)?.severity_claimed}，因污点流未证成已降级`"
                    >↓ 由 {{ (g.representative.raw as any)?.severity_claimed }} 降级</div>
                  </td>
                  <td>
                    <span class="flow-badge" :class="flowBadge(g.representative).tone" :title="flowBadge(g.representative).detail">{{ flowBadge(g.representative).label }}</span>
                  </td>
                  <td class="muted"><code>{{ g.file }}</code></td>
                  <td>
                    <button v-if="g.count > 1" type="button" class="ghost-button" @click="toggleA1Group(g.key)">
                      {{ a1Expanded.has(g.key) ? "收起" : g.lines.slice(0, 3).join(", ") + (g.lines.length > 3 ? " …" : "") }}
                    </button>
                    <span v-else>{{ g.lines[0] }}</span>
                  </td>
                  <td class="muted">{{ truncateText(g.description, 110) }}</td>
                </tr>
                <tr v-if="a1Expanded.has(g.key)">
                  <td colspan="6" class="muted">全部命中行号：{{ g.lines.join(", ") }}</td>
                </tr>
              </template>
            </tbody>
          </table>
          </div>
          <div v-else-if="overviewStageFindings.length" class="table-wrap cols-5">
          <table>
            <thead><tr><th>Finding</th><th>严重度</th><th>可达性 / 确认态</th><th>位置</th><th>AI 分析（入口 → 危险函数）</th></tr></thead>
            <tbody>
                <tr v-for="finding in overviewStageRows" :key="`${activeStageValue.key}-${finding.id}`">
                  <td>
                    <span v-if="isBusinessLogic(finding)" class="badge badge-info" :title="`${businessLogicLabel(finding)}：作为 A1 一级 family findings，与技术漏洞共用同一条 D 阶段验证链路`">{{ businessLogicLabel(finding) }}</span>
                    <!-- 2026-09-18（A2 方案二）：被聚合吸收的成员补行。其证据已并入所属聚合 finding，
                         此处仅保留自身的文件/行，用于覆盖率统计与 IAST 关联桥。 -->
                    <span
                      v-if="isAbsorbedFinding(finding)"
                      class="badge"
                      :title="`该节点已被聚合吸收（归属组 ${String((finding.raw as any)?.absorbed_by_group_key || '')}），证据并入所属聚合发现，不单独参与 D2 验证`"
                    >聚合成员</span>
                    <strong>{{ displayFindingLabel(finding) }}</strong>
                    <div class="muted">{{ displayFindingPath(finding) }}</div>
                  </td>
                <td>
                  <SeverityBadge :level="finding.severity" />
                  <div
                    v-if="severityDowngraded(finding)"
                    class="muted"
                    :title="`LLM 原始声称 ${(finding.raw as any)?.severity_claimed}，因污点流未证成已降级`"
                  >↓ 由 {{ (finding.raw as any)?.severity_claimed }} 降级</div>
                </td>
                <td>
                  <span class="flow-badge" :class="flowBadge(finding).tone" :title="flowBadge(finding).detail">{{ flowBadge(finding).label }}</span>
                  <div v-if="flowDims(finding)" class="muted">{{ flowDims(finding) }}</div>
                </td>
                <td>{{ finding.file_path }}:{{ finding.line }}</td>
                <td class="muted">
                  <template v-if="activeStageValue.key === 'a1'">{{ truncateText(String((finding.raw as any)?.description || ""), 110) }}</template>
                  <template v-else>{{ aiAnalysisSummary(finding) }}</template>
                </td>
              </tr>
            </tbody>
          </table>
          </div>
          <!-- Q7 去密：默认只渲染前 20 行，其余按需展开（避免一屏几百行的数字墙）。 -->
          <div v-if="overviewStageFindings.length > OVERVIEW_ROW_LIMIT" class="row gap-sm wrap">
            <button type="button" class="ghost-button tiny" @click="overviewRowsExpanded = !overviewRowsExpanded">
              {{ overviewRowsExpanded ? "收起" : `展开全部 ${overviewStageFindings.length} 条` }}
            </button>
            <span class="muted small">当前显示 {{ overviewStageRows.length }} / {{ overviewStageFindings.length }} 条</span>
          </div>
          <div v-else-if="!store.findings.length" class="muted">数据尚未加载，请稍候或刷新页面。</div>
          <div v-else class="muted">
            当前任务共 {{ store.findings.length }} 条 finding，其中 {{ overviewStageFindings.length }} 条标记为 {{ activeStageValue.key.toUpperCase() }}。请检查 findings 的 sources 字段是否包含 {{ activeStageValue.key.toUpperCase() }}。
          </div>
        </div>

        <!-- AP 攻击计划 -->
        <div v-if="activeStageValue.key === 'attack_plan'" class="stage-subpanel">
          <h4>AP 攻击计划：A2 假说 → 即将执行的 POC</h4>
          <p class="muted">A2 阶段登记的每个 TriggerSpec，在此被投射为一份可读的攻击计划：准备打哪个端点、注入哪个参数、用什么 payload、如何判定成功。D1 实际重放结果见 D1 面板，运行时命中见 I1 面板。</p>
          <div v-if="attackPlan && attackPlan.entries && attackPlan.entries.length" class="stack gap-sm">
            <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="apFlowCounts" />
            <div class="stage-metrics">
              <div class="metric-pill"><span class="muted">计划条目</span><strong>{{ attackPlan.plan_count }}</strong></div>
              <div class="metric-pill" v-for="(c, fam) in (attackPlan.by_family || {})" :key="fam"><span class="muted">{{ fam }}</span><strong>{{ c }}</strong></div>
            </div>
            <div class="table-wrap cols-8">
            <table>
              <thead><tr><th>#</th><th>目标端点</th><th>方法</th><th>注入参数</th><th>漏洞族</th><th>攻击载荷（PoC）</th><th>成功判定</th><th>运行时命中</th></tr></thead>
              <tbody>
                <tr v-for="e in visibleApEntries" :key="(e.spec_id ?? e.order)">
                  <td>{{ e.order }}</td>
                  <td><code>{{ e.endpoint }}</code></td>
                  <td>{{ e.method }}</td>
                  <td>{{ e.param }} <span class="muted">/ {{ e.location }}</span></td>
                  <td><span class="badge badge-info">{{ familyLabel(e.family) }}</span></td>
                  <td class="muted wrap-break"><code>{{ decodePoc(e.poc_preview) }}</code></td>
                  <td class="muted">{{ e.success_signal || '—' }}</td>
                  <td>
                    <span class="badge" :class="runtimeBadgeClass(e.runtime_status)">{{ runtimeLabel(e.runtime_status) }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
            </div>
          </div>
          <div v-else class="muted">该任务尚未生成攻击计划（可能 A2 未登记 TriggerSpec，或 verification 未启用）。重新运行任务即可生成。</div>
        </div>

        <!-- D1 -->
        <div v-if="activeStageValue.key === 'd1'" class="stage-subpanel">
          <h4>D1 操作器：A2 假说 → 运行时重放</h4>
          <p class="muted">D1 阶段把 A2 语义分析产出的 TriggerSpec 自动喂给 IAST/DAST 运行时验证。若启用了 IDOR asset replay，会额外执行资产重放；否则仅展示 A2→D1 自动重放结果。</p>
          <div v-if="stageMetric('d1', 'candidate_count') !== '0' || stageMetric('d1', 'finding_count') !== '0' || stageMetric('d1', 'iast_arrivals') !== '0'" class="stage-metrics">
            <div class="metric-pill"><span class="muted">TriggerSpec</span><strong>{{ stageMetric("d1", "candidate_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">DAST impact</span><strong>{{ stageMetric("d1", "finding_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">IAST arrival</span><strong>{{ stageMetric("d1", "iast_arrivals") }}</strong></div>
          </div>
          <p v-else class="muted">该阶段暂无 A2→D1 自动重放明细。</p>

          <!-- #2D D1 阶段：列出实际重放的 TriggerSpec 明细（靶面 / 参数 / canary 身份段 / 来源） -->
          <div v-if="d1Specs.length" class="stack gap-xs mt-sm">
            <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="d1FlowCounts" />
            <h5>实际重放的 TriggerSpec 明细（{{ d1Specs.length }}）</h5>
            <div class="table-wrap cols-7">
            <table>
              <thead>
                <tr>
                  <th>目标端点</th>
                  <th>方法</th>
                  <th>注入参数</th>
                  <th>位置</th>
                  <th>漏洞族</th>
                  <th>探针标识</th>
                  <th>来源</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="s in visibleD1Specs" :key="(s.id ?? s.canary_identity)">
                  <td><code>{{ s.endpoint }}</code></td>
                  <td>{{ s.http_method }}</td>
                  <td>{{ s.param_name }}</td>
                  <td>{{ s.param_location }}</td>
                  <td><span class="badge badge-info">{{ familyLabel(s.family) }}</span></td>
                  <td class="muted">{{ maskCanary(s.canary_identity) }}</td>
                  <td><span class="badge" :class="s.source === 'a2' ? 'badge-success' : 'badge-muted'">{{ s.source }}</span></td>
                </tr>
              </tbody>
            </table>
            </div>
          </div>
        </div>

        <!-- I1：IAST 运行时监听（监听器视图，不展示 SAST 关联） -->
        <div v-if="activeStageValue.key === 'i1'" class="stage-subpanel">
          <h4>IAST 运行时监听</h4>
          <div v-if="iastListener && iastListener.total_events > 0" class="stack gap-sm">
            <div class="stage-metrics">
              <div class="metric-pill"><span class="muted">捕获事件</span><strong>{{ iastListener.total_events }}</strong></div>
              <div class="metric-pill"><span class="muted">Sink 命中</span><strong>{{ iastListener.sink_hit_events }}</strong></div>
              <div class="metric-pill"><span class="muted">Canary 到达</span><strong>{{ iastListener.canary_arrivals }}</strong></div>
              <div class="metric-pill"><span class="muted"> distinct sink</span><strong>{{ iastListener.distinct_sink_count }}</strong></div>
            </div>
            <div v-if="iastListener.sessions?.length" class="row wrap gap-xs">
              <span
                v-for="s in iastListener.sessions"
                :key="s.id"
                class="badge"
                :class="s.status === 'ready' ? 'badge-success' : 'badge-muted'"
              >探针 {{ s.app_name }} · {{ s.status }}</span>
            </div>
            <div v-if="iastListener.sink_methods_sample?.length" class="muted">
              已观测 sink：{{ iastListener.sink_methods_sample.join("、") }}
            </div>
          </div>
          <div v-else-if="iastListener" class="stack gap-sm">
            <p class="muted">探针已就绪，但未收到运行时事件。</p>
            <p class="muted">可能原因：D1 重放未命中目标、请求未携带 canary、探针未覆盖对应 sink，或 sink 门控未触发。请到 Workspace → IAST 检查探针心跳与上报日志。</p>
            <div v-if="iastListener.sessions?.length" class="row wrap gap-xs">
              <span
                v-for="s in iastListener.sessions"
                :key="s.id"
                class="badge"
                :class="s.status === 'ready' ? 'badge-success' : 'badge-muted'"
              >探针 {{ s.app_name }} · {{ s.status }}</span>
            </div>
          </div>
          <div v-else class="muted">IAST 探针尚未上报运行时事件。</div>

          <!-- #1 诊断面板：暴露不属于本 task 的跨任务 canary 事件（探针内存残留/历史重放未清理） -->
          <div v-if="iastDiagnostics && iastDiagnostics.unmatched_count > 0" class="stack gap-sm mt-sm">
            <h5>跨任务 canary 干扰诊断</h5>
            <p class="muted">
              本 task 登记的 TriggerSpec 共 {{ iastDiagnostics.current_task_spec_count }} 条，但 IAST 观测到
              {{ iastDiagnostics.unmatched_count }} 条属于其它 task 的 canary 事件（探针内存残留或历史重放未清理）。
              这些事件不会计入本 task 的 I1 关联 —— D1 重放前已通过「旧 canary 缓存清空」按本 task 身份段精准隔离。
            </p>
            <FlowTypeSwitch v-model="flowFilter" />
            <ul class="stack gap-xs">
              <li v-for="(e, idx) in visibleUnmatched.slice(0, 12)" :key="idx" class="muted">
                <code>{{ e.canary_identity }}</code>
                <span>→ 属 task {{ e.owner_task_id ?? '?' }}（{{ e.event_type || '事件' }}，状态 {{ e.canary_state || '?' }}）</span>
              </li>
            </ul>
          </div>
        </div>

        <!-- D2：sink 注入点核实 + 逐漏洞证据链（Q4） -->
        <div v-if="activeStageValue.key === 'd2'" class="stage-subpanel">
          <h4>D2 校验器：sink 注入点核实 + 证据链</h4>
          <p v-if="d2Verify.it > 0" class="stage-hint">D2 验证迭代：第 {{ d2Verify.it }} 轮，本轮可利用 {{ d2Verify.exploitable }} 条。</p>
          <div class="stage-metrics">
            <div class="metric-pill"><span class="muted">已验证</span><strong>{{ stageMetric("d2", "verified_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">结果点有害</span><strong>{{ stageMetric("d2", "harmful_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">sink 到达</span><strong>{{ stageMetric("d2", "sink_reached_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">确认可利用</span><strong>{{ stageMetric("d2", "confirmed_exploitable_count") }}</strong></div>
            <div class="metric-pill"><span class="muted">已验证 POC</span><strong>{{ stageMetric("d2", "verified_poc_count") }}</strong></div>
          </div>
          <p class="muted mt-sm">D2 校验器逐漏洞核实 sink 点是否真实注入成功（含 IAST 命中 / 投放 payload / taint 路径），证据链如下。</p>

          <div v-if="Object.keys(d2ByFamily).length" class="stack gap-xs mt-sm">
            <h5>按漏洞族分布</h5>
            <div class="row wrap gap-xs">
              <span v-for="(c, fam) in d2ByFamily" :key="fam" class="badge badge-muted">{{ fam }} · {{ c }}</span>
            </div>
          </div>

          <div v-if="d2Details.length" class="stack gap-sm mt-sm">
            <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="d2FlowCounts" />
            <h5>逐漏洞证据链（{{ d2Details.length }}）</h5>
            <div v-for="d in visibleD2Details" :key="d.vulnerability_hash_v2 || (d.type + (d.endpoint||''))" class="iast-finding-card stack gap-xs">
              <div class="row between wrap gap-sm">
                <div class="stack gap-xs">
                  <div class="row wrap gap-xs">
                    <strong>{{ d.type }}</strong>
                    <span class="badge" :class="d.d2_harmful ? 'badge-danger' : 'badge-muted'">{{ d.d2_harmful ? '结果点有害' : '未证实有害' }}</span>
                    <span v-if="d.trigger_spec_provided" class="badge badge-success">有 TriggerSpec</span>
                    <span v-else class="badge badge-muted">无靶可重放</span>
                  </div>
                  <div class="muted" v-if="d.endpoint">{{ d.http_method }} {{ d.endpoint }}#{{ d.param_name }}</div>
                  <div class="muted" v-if="d.sink_method">sink：{{ d.sink_method }} <template v-if="d.sink_file">@ {{ d.sink_file }}:{{ d.sink_line }}</template></div>
                </div>
              </div>
              <div class="row wrap gap-xs muted">
                <span>IAST：{{ d.iast_state || '—' }}</span>
                <span>DAST reached：{{ d.dast_reached ? '是' : '否' }}</span>
                <span v-if="d.status_code">HTTP {{ d.status_code }}</span>
                <span>置信：{{ d.d2_confidence || '—' }}</span>
                <span v-if="d.canary_identity">探针标识：<code>{{ maskCanary(d.canary_identity) }}</code></span>
              </div>
              <div class="muted" v-if="d.d2_reason">{{ d.d2_reason }}</div>
              <div class="muted" v-if="d.d2_evidence"><strong>证据片段：</strong>{{ d.d2_evidence }}</div>
              <div v-if="d.taint_path && d.taint_path.length" class="stack gap-xs">
                <details>
                  <summary class="muted">taint 传播路径（{{ d.taint_path.length }} 节点）</summary>
                  <ol class="taint-path">
                    <li v-for="(n, i) in d.taint_path" :key="i">
                      <span class="badge badge-muted">{{ n.role || n.stage || 'node' }}</span>
                      <code>{{ n.origin || n.node || n.signature || '' }}</code>
                    </li>
                  </ol>
                </details>
              </div>
              <div v-if="d.per_spec_decisions && d.per_spec_decisions.length" class="stack gap-xs">
                <div class="muted"><strong>I2 逐 spec 裁决：</strong></div>
                <div v-for="(ps, i) in d.per_spec_decisions" :key="i" class="row wrap gap-xs">
                  <span class="badge" :class="iastStateTone(ps.final_state)">{{ ps.final_state }}</span>
                  <span class="muted">{{ ps.reason }}</span>
                </div>
              </div>
            </div>
          </div>
          <div v-else class="muted mt-sm">D2 已对本任务的漏洞执行逐漏洞校验，但本次未在运行时取得确定性证据：A2 给出的利用链证明不足（如反序列化两步链无法被单步重放驱动），或 IAST 未观测到 canary 抵达目标 sink。可结合「按漏洞族分布」与 D1 / I1 面板判断，并在 A2 阶段补充利用链证明后重跑。</div>
        </div>

        <!-- I2：IAST 关联 + 裁决（SAST 假说 ⇄ IAST 观测覆盖率差集） -->
        <div v-if="activeStageValue.key === 'i2'" class="stage-subpanel">
          <h4>IAST 关联（I2 裁决）</h4>
          <div class="stage-metrics">
            <div class="metric-pill"><span class="muted">SAST 假说</span><strong>{{ iastStats.total_hypotheses }}</strong></div>
            <div class="metric-pill"><span class="muted">IAST 观测</span><strong>{{ iastStats.iast_observed }}</strong></div>
            <div class="metric-pill"><span class="muted">潜在命中</span><strong>{{ iastStats.confirmed_runtime }}</strong></div>
            <div class="metric-pill"><span class="muted">真命中</span><strong>{{ iastStats.exploit_confirmed }}</strong></div>
            <div class="metric-pill"><span class="muted">真命中率</span><strong>{{ pct(iastStats.exploit_confirmed_ratio) }}</strong></div>
          </div>
          <div v-if="iastFindings.length" class="stack gap-sm">
            <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="i2FlowCounts" />
            <div v-for="f in visibleI2Findings" :key="f.vulnerability_hash_v2" class="iast-finding-card stack">
              <div class="row between wrap gap-sm">
                <div class="stack gap-xs">
                  <div class="row wrap gap-xs">
                    <strong>{{ f.finding_type }}</strong>
                    <span class="badge" :class="`badge-${iastStateTone(f)}`">{{ iastStateLabel(f) }}</span>
                    <span v-if="f.iast?.canary_observed" class="badge badge-muted">canary_observed</span>
                    <span v-if="f.iast?.exploit_confirmed" class="badge badge-danger">真命中</span>
                  </div>
                  <div class="muted">{{ f.file_path }}:{{ f.line }}</div>
                  <div class="muted">来源 {{ f.sources.join(" + ") }} · 事件 {{ f.iast?.event_count ?? 0 }}</div>
                </div>
              </div>
              <div v-if="iastHypothesisMap.get(f.vulnerability_hash_v2)" class="iast-detail stack gap-xs">
                <div class="row wrap gap-xs">
                  <span class="muted">D2 校验：{{ iastHypothesisMap.get(f.vulnerability_hash_v2)!.d2_verdict }}</span>
                  <span class="muted">{{ iastHypothesisMap.get(f.vulnerability_hash_v2)!.included_in_report ? "已纳入报告" : "未纳入报告" }}</span>
                </div>
              </div>
            </div>
          </div>
          <div v-else class="muted">暂无 IAST 关联数据。</div>

          <div v-if="iastAdjudication" class="stack gap-xs mt-sm">
            <h4>覆盖率差集（I2 裁决）</h4>
            <div class="stage-metrics">
              <div class="metric-pill"><span class="muted">matched</span><strong>{{ iastAdjudicationStats.matched ?? "-" }}</strong></div>
              <div class="metric-pill"><span class="muted">假说无观测</span><strong>{{ iastAdjudicationStats.hypothesis_only ?? "-" }}</strong></div>
              <div class="metric-pill"><span class="muted">观测无假说</span><strong>{{ iastAdjudicationStats.observed_only ?? "-" }}</strong></div>
              <div class="metric-pill"><span class="muted">疑似误报</span><strong>{{ iastAdjudicationStats.likely_false_positive ?? "-" }}</strong></div>
            </div>
          </div>
        </div>

        <!-- Reporting -->
        <div v-if="activeStageValue.key === 'reporting'" class="stage-subpanel">
          <h4>生成报告</h4>
          <p class="muted">{{ stageSummary("reporting") }}</p>
          <div v-if="store.reports.length" class="stack gap-xs">
            <div v-for="report in store.reports" :key="report.id" class="row between gap-sm report-row" @click="selectReport(report)">
              <span>{{ report.report_type }}</span>
              <span class="muted">{{ report.file_path }}</span>
            </div>
          </div>
          <div v-else class="muted">暂无报告。</div>
          <!-- Q3：结构化结果看板。与既有 Markdown 报告并存（不替换、不回归），
               报告正文仍走原 RoundReporter/ReportViewer 入口。 -->
          <ReportDashboard
            v-if="store.reports.length"
            class="report-dashboard"
            :report-id="store.selectedReport?.id ?? store.reports[0]?.id ?? null"
          />
        </div>
      </section>
    </section>

    <!-- 2026-09-17（待请示批准）：单 task 运行时运维视图。
         用户诉求是「直观对应 task 的总结看板，替代纯文字不直观的报告」，故用状态卡 +
         端口徽章 + 事件流呈现，而不是把 /runtime 的字段平铺成文字。 -->
    <section v-else-if="selectedTab === 'Ops'" class="stack">
      <section class="card stack">
        <div class="row between wrap gap-sm">
          <h3>运行时运维</h3>
          <div class="row gap-sm">
            <span class="muted">每 15 秒自动刷新</span>
            <button type="button" class="ghost-button" @click="loadRuntime">立即刷新</button>
          </div>
        </div>
        <p class="muted">
          只看这一个任务的运行实况：进程锁、进度心跳与卡死判定、目标端口可达性、最近事件流、AI 调用。
          跨任务的运营度量（成本 / 吞吐 / 覆盖度）在侧边栏「运维看板」。
        </p>

        <div v-if="runtimeError" class="muted">运维快照拉取失败：{{ runtimeError }}</div>
        <div v-else-if="!runtime" class="muted">加载中…</div>
        <div v-else class="stack gap-sm">
          <div class="ops-grid">
            <div class="stat-card">
              <span class="muted">任务状态</span>
              <strong class="num">{{ runtime.status || "—" }}</strong>
            </div>
            <div class="stat-card">
              <span class="muted">扫描进程</span>
              <strong class="num">{{ runtime.subprocess_lock ? "持有锁（运行中）" : "未持有锁" }}</strong>
            </div>
            <div class="stat-card">
              <span class="muted">卡死检测</span>
              <strong class="num">{{ (runtime.progress || {}).stuck ? "疑似卡死" : "正常" }}</strong>
            </div>
            <div class="stat-card">
              <span class="muted">进度心跳</span>
              <strong class="num">{{ runtimeProgressAge }}</strong>
            </div>
          </div>

          <div class="stack gap-xs">
            <h4>端口可达性</h4>
            <div class="row wrap gap-sm">
              <span
                v-for="(up, port) in (runtime.ports || {})"
                :key="port"
                class="port-chip"
                :class="up ? 'is-up' : 'is-down'"
              >{{ port }} · {{ up ? "在监听" : "未监听" }}</span>
            </div>
          </div>

          <div
            v-if="(runtime.ai_calls || {}).total !== null && (runtime.ai_calls || {}).total !== undefined"
            class="stack gap-xs"
          >
            <h4>AI 调用</h4>
            <p class="muted">
              运行窗口内 {{ runtime.ai_calls.total }} 次调用，输入
              {{ runtime.ai_calls.input_tokens }} / 输出 {{ runtime.ai_calls.output_tokens }} tokens。
              {{ runtime.ai_calls.note }}
            </p>
          </div>

          <div class="stack gap-xs">
            <h4>最近事件流</h4>
            <div v-if="(runtime.recent_events || []).length" class="stack gap-xs">
              <div v-for="ev in (runtime.recent_events || [])" :key="ev.id" class="row between gap-sm">
                <span>{{ ev.event_type }}</span>
                <span class="muted">{{ ev.created_at }}</span>
              </div>
            </div>
            <div v-else class="muted">暂无事件。</div>
          </div>
        </div>
      </section>

      <!-- 合并后的「运维 / 日志」tab：实时日志流（原【日志】tab 内容并入此处） -->
      <section class="card stack">
        <div>
          <h3>实时日志</h3>
          <p class="muted">WebSocket 事件流在此实时滚动；D2 验证与报告阶段页面会自动刷新发现与报告。</p>
        </div>
        <div class="log-stream">
          <div v-for="item in logs" :key="item.id" class="log-line" :class="`log-${item.tone}`">
            <small class="muted">{{ item.created_at || "" }}</small>
            <span>{{ item.text }}</span>
          </div>
        </div>
      </section>
    </section>

    <section v-else-if="selectedTab === 'Findings'" class="stack">
      <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="findingsFlowCounts" />
      <section class="card stack">
        <div class="row between wrap gap-sm">
          <h3>Stage result summary</h3>
          <div class="row wrap gap-sm">
            <button
              v-for="item in stageResultTabs"
              :key="item.key"
              type="button"
              class="ghost-button"
              :class="{ active: selectedResultStage === item.key }"
              @click="selectedResultStage = item.key"
            >
              {{ item.label }}
            </button>
          </div>
        </div>
        <div class="muted">{{ stageSummary(selectedResultStage) }}</div>

        <!-- #2C A2 漏斗：A2 产出 → 已登记 TriggerSpec → 未解析跳过（含原因） -->
        <div v-if="a2Funnel && selectedResultStage === 'a2'" class="stack gap-sm mt-sm">
          <h4>A2 → TriggerSpec 漏斗</h4>
          <div class="stage-metrics">
            <div class="metric-pill"><span class="muted">A2 产出 findings</span><strong>{{ a2Funnel.total_a2_findings ?? 0 }}</strong></div>
            <div class="metric-pill"><span class="muted">已登记 TriggerSpec</span><strong>{{ a2Funnel.registered_trigger_specs ?? 0 }}</strong></div>
            <div class="metric-pill"><span class="muted">未解析跳过</span><strong>{{ a2Funnel.skipped_unresolved ?? 0 }}</strong></div>
            <div class="metric-pill"><span class="muted">重复跳过</span><strong>{{ a2Funnel.skipped_duplicate ?? 0 }}</strong></div>
          </div>
          <FlowTypeSwitch v-model="flowFilter" :show-counts="true" :counts="unresolvedFlowCounts" />
          <ul v-if="visibleUnresolved.length" class="stack gap-xs">
            <li v-for="(r, idx) in visibleUnresolved.slice(0, 20)" :key="idx" class="muted">
              <code>{{ r.vulnerability_hash_v2 }}</code>
              <span>未解析：{{ r.reason }}（param={{ r.param_name || '?' }}，route={{ r.route || '?' }}）</span>
            </li>
          </ul>
        </div>
        <div v-if="visibleStageFindings.length" class="table-wrap cols-3">
        <table>
          <thead>
            <tr>
              <th>Finding</th>
              <th>Status</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="finding in visibleStageFindings" :key="`${selectedResultStage}-${finding.id}`">
              <td>
                <strong>{{ displayFindingLabel(finding) }}</strong>
                <div class="muted">{{ displayFindingPath(finding) }}</div>
              </td>
              <td>{{ stageFindingStatus(finding, selectedResultStage) }}</td>
              <td>{{ finding.file_path }}:{{ finding.line }}</td>
            </tr>
          </tbody>
        </table>
        </div>
        <div v-else class="muted">{{ emptyStageResultText }}</div>
      </section>

      <section class="card stack">
        <div>
          <h3>Canonical findings</h3>
          <p class="muted">逐条展示验证裁决与执行证据，不再混进主时间线里。</p>
        </div>
        <div v-if="visibleFindings.length" class="table-wrap cols-8">
        <table>
          <thead>
            <tr>
              <th>Finding chain</th>
              <th>Severity</th>
              <th>Location</th>
              <th>A2 静态判定</th>
              <th>验证状态</th>
              <th>Hash / AI</th>
              <th>Evidence</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="finding in visibleFindings" :key="finding.id">
              <td>
                <strong>{{ displayFindingLabel(finding) }}</strong>
                <span
                  v-if="iastRuntimeState(finding)"
                  class="badge"
                  :class="`badge-${iastRuntimeTone(iastRuntimeState(finding))}`"
                >{{ iastRuntimeState(finding) }}</span>
                <div v-if="finding.raw?.is_primary_chain" class="muted">Primary chain</div>
                <div class="muted">{{ String(finding.raw?.proof_tier || "-") }}</div>
              </td>
              <td><SeverityBadge :level="finding.severity" /></td>
              <td>{{ finding.file_path }}:{{ finding.line }}</td>
              <td>
                <span class="badge" :class="`badge-${staticVerdictTone(finding)}`" :title="staticVerdictValue(finding)">{{ staticVerdictShort(finding) }}</span>
              </td>
              <td>
                <span class="badge" :class="`badge-${verificationStateTone(finding)}`" :title="verificationStateHint(finding)">{{ verificationStateLabel(finding) }}</span>
              </td>
              <td>
                <code>{{ hashLabel(finding) }}</code>
                <div class="muted">{{ aiReviewStatus(finding) }}</div>
              </td>
              <td>
                <div>{{ displayFindingPath(finding) }}</div>
                <div v-if="verificationStatusLabel(finding)" class="muted">Decision: {{ verificationStatusLabel(finding) }}</div>
                <div v-if="verificationReason(finding)" class="muted">Reason: {{ verificationReason(finding) }}</div>
                <div v-if="matchedOutcomesText(finding)" class="muted">Matched outcomes: {{ matchedOutcomesText(finding) }}</div>
                <div v-if="requestsText(finding)" class="muted">Requests: {{ requestsText(finding) }}</div>
                <div v-if="sideEffectsText(finding)" class="muted">Side effects: {{ sideEffectsText(finding) }}</div>
                <div v-if="cleanupText(finding)" class="muted">Cleanup: {{ cleanupText(finding) }}</div>
                <div v-if="fixSummary(finding)" class="muted">Fix: {{ fixSummary(finding) }}</div>
              </td>
              <td>
                <div class="row wrap gap-xs">
                  <button class="ghost-button tiny" type="button" @click="generateFix(finding)">修复建议</button>
                  <button class="ghost-button tiny" type="button" @click="generatePatch(finding)">补丁草案</button>
                </div>
                <div class="row wrap gap-xs mt-xs">
                  <button class="ghost-button tiny" type="button" @click="humanDecision(finding, 'true_positive')">采纳有效</button>
                  <button class="ghost-button tiny" type="button" @click="humanDecision(finding, 'false_positive')">采纳误报</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        </div>
        <div v-else class="muted">该任务暂无可展示的 findings。</div>
      </section>
    </section>

    <section v-else-if="selectedTab === 'Reports'" class="stack">
      <RoundReporter v-if="store.selectedTask" :task-id="store.selectedTask.id" :baseline-id="9" />
    </section>

    <section v-else-if="selectedTab === 'HITL'" class="card stack">
      <div class="divider" />

      <div class="stack gap-sm">
        <div>
          <h3>HITL controls（人工介入）</h3>
          <p class="muted">
            人工介入（Human-In-The-Loop）用于约束会执行「危险动态动作」的智能体工具，防止自动化流程在无人确认的情况下真打目标。
            三档审批模式：off（不拦截）／ask_on_risky_tools（仅对不可逆动作问询）／strict（全部动态工具都需人工放行）。
            下方「待处理动作」队列列出当前被拦截的不可逆动作，你可逐条或批量「放行／允许工具／拒绝」；
            此外，在【发现】tab 的 Canonical findings 表里，每条发现也能由你「采纳有效／采纳误报」，这些人工裁决会回写系统、修正误报与置信度。
          </p>
        </div>
        <div class="row wrap gap-sm">
          <label class="stack gap-xs">
            <span class="muted">Approval mode</span>
            <select v-model="approvalModeDraft">
              <option value="off">off</option>
              <option value="ask_on_risky_tools">ask_on_risky_tools</option>
              <option value="strict">strict</option>
            </select>
          </label>
          <label class="stack gap-xs flex-1">
            <span class="muted">Tool allowlist</span>
            <input v-model="allowlistDraft" type="text" placeholder="tool ids, comma separated" />
          </label>
          <button type="button" class="button" @click="saveHitlSettings" :disabled="!store.selectedTask">Save</button>
        </div>

        <!-- ⑤-D 挂起 / 恢复：复核期间持有任务；恢复=按已更新 allowlist 重新提交=回填 -->
        <div class="row wrap gap-sm">
          <button
            v-if="store.selectedTask && store.selectedTask.status !== 'suspended'"
            type="button" class="ghost-button" :disabled="!canSuspend" @click="suspendSelectedTask"
          >挂起（复核持有）</button>
          <button
            v-if="store.selectedTask && store.selectedTask.status === 'suspended'"
            type="button" class="button" @click="resumeSelectedTask"
          >恢复并回填</button>
          <span v-if="store.selectedTask && store.selectedTask.status === 'suspended'" class="badge badge-muted">已挂起（未被实际拦截，仅供复核）</span>
          <span v-if="store.selectedTask && store.selectedTask.status === 'running'" class="muted">运行中不可挂起</span>
        </div>

        <!-- ③ 异步非阻塞专属横幅：出现待批动作或挂起态时提示，不阻断页面查看 -->
        <div
          v-if="pendingActionsCount > 0 || (store.selectedTask && store.selectedTask.status === 'suspended')"
          class="stack gap-xs"
          style="background: var(--surface-tint-warn); border: 1px solid var(--sev-medium); border-radius: var(--radius-md); padding: 10px 12px;"
        >
          <div class="row wrap gap-sm" style="justify-content: space-between;">
            <strong>人入环待裁决（异步，不阻断页面查看）</strong>
            <span class="muted">{{ pendingActionsCount }} 条待处理 · {{ irreversibleCount }} 条不可逆</span>
          </div>
          <div v-if="store.selectedTask && store.selectedTask.status === 'suspended'" class="muted">
            当前任务已挂起（复核持有，未被实际拦截，靶场状态未改变）。
          </div>
        </div>

        <div class="muted">Pending actions: {{ pendingActionsCount }}</div>
        <div v-if="pendingActions.length" class="stack gap-sm">
          <div class="row wrap gap-sm">
            <button type="button" class="ghost-button" @click="toggleSelectAll">{{ allSelected ? '取消全选' : '全选' }}</button>
            <button type="button" class="ghost-button" :disabled="!selectedActionIds.length" @click="batchResolve('approved')">批量放行</button>
            <button type="button" class="ghost-button danger-outline" :disabled="!selectedActionIds.length" @click="batchResolve('rejected')">批量拒绝</button>
            <span class="muted">已选 {{ selectedActionIds.length }}</span>
          </div>
          <!-- ② 批量裁决不可逆红色警告：选中含不可逆动作时高亮提示，放行将真实打目标 -->
          <div
            v-if="selectedActionIds.length && batchHasIrreversible"
            class="stack gap-xs"
            style="background: var(--surface-tint-danger); border: 1px solid var(--sev-critical); border-radius: var(--radius-md); padding: 10px 12px;"
          >
            <div class="muted">
              <strong>警告：已选 {{ selectedIrreversibleCount }} 条不可逆动作（money_out / data_destroy / mass_assignment / status_overwrite / credential_mutation / destructive_payload 等），放行将真实打目标，请确认后再操作。</strong>
            </div>
          </div>
          <!-- ① 按真实动作类别分组（类别取自 decide_hitl_gate 的 act.category 单一真相源） -->
          <div v-for="group in groupedPendingActions" :key="group.category" class="stack gap-sm">
            <div class="row wrap gap-sm" style="justify-content: space-between;">
              <strong>{{ group.category }}（{{ group.actions.length }}）</strong>
              <span v-if="group.hasIrreversible" class="badge badge-danger">含不可逆 · 待人工放行</span>
              <span v-else class="badge badge-muted">待人工放行</span>
            </div>
            <div v-for="action in group.actions" :key="String(action.id || '')" class="card subtle stack gap-xs">
              <div class="row wrap gap-sm" style="justify-content: space-between;">
                <label class="row gap-xs">
                  <input type="checkbox" :value="String(action.id || '')" v-model="selectedActionIds" />
                  <strong>{{ String(action.tool_id || "unknown-tool") }}</strong>
                </label>
                <span class="muted">风险 {{ String(action.risk_level || "-") }} · 阶段 {{ String(action.stage || "-") }}</span>
              </div>
              <div class="muted">{{ String(action.reason || "") }}</div>
              <!-- ⑤-C 两阶段只读先行：展示将投放的不可逆动作（只读探明，未实际执行） -->
              <div v-if="roPlan(action).route" class="card subtle stack gap-xs" style="margin-top: 4px;">
                <div class="muted"><strong>只读探明的将投放动作：</strong></div>
                <div class="muted">{{ String(roPlan(action).method || "?") }} {{ String(roPlan(action).route || "") }}</div>
                <div class="muted">类别：{{ String(roPlan(action).category || "-") }} · 工具：{{ String(roPlan(action).tool_id || "-") }} · 模式：{{ String(roPlan(action).approval_mode || "-") }}</div>
                <div class="muted">{{ String(roPlan(action).reason || "") }}</div>
                <div class="muted">{{ String(roPlan(action).effect || "") }}</div>
              </div>
              <div class="row wrap gap-sm">
                <button type="button" class="button" @click="resolvePendingAction(String(action.id || ''), 'approved')">本次放行</button>
                <button type="button" class="ghost-button" @click="allowlistAndApprove(String(action.id || ''), String(action.tool_id || ''))">本任务允许该工具</button>
                <button type="button" class="ghost-button danger-outline" @click="resolvePendingAction(String(action.id || ''), 'rejected')">拒绝</button>
              </div>
            </div>
          </div>
        </div>

        <!-- ⑤-A 审计呈现面：持久化的 guard 决策（含放行/拦截），跨重启可查 -->
        <div class="divider" />
        <div class="stack gap-xs">
          <div class="row wrap gap-sm" style="justify-content: space-between;">
            <h4>HITL 审计轨迹（人入环关键决策）</h4>
            <button type="button" class="ghost-button" :disabled="!store.selectedTask" @click="refreshAudit">刷新</button>
          </div>
          <div v-if="hitlAudit.length" class="stack gap-xs">
            <div v-for="entry in hitlAudit" :key="entry.id" class="card subtle stack gap-xs">
              <div class="row wrap gap-sm" style="justify-content: space-between;">
                <strong>{{ entry.action === 'gated' ? '拦截' : '放行' }} · {{ String(entry.category || 'none') }}</strong>
                <span class="muted">{{ String(entry.method || '') }} {{ String(entry.route || '') }}</span>
              </div>
              <div class="muted">{{ String(entry.reason || '') }}</div>
              <!-- ④ decide_hitl_gate 决策依据 + detail 渲染：展示闸门判定链 / 短接理由 -->
              <div v-if="detailText(entry.detail)" class="card subtle stack gap-xs" style="margin-top: 4px;">
                <div class="muted"><strong>闸门决策链 / 短接理由（decide_hitl_gate）：</strong></div>
                <pre :style="{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '12px', background: 'var(--color-surface-3)', padding: '8px 10px', borderRadius: 'var(--radius-sm)', margin: 0, maxHeight: '240px', overflow: 'auto' }">{{ detailText(entry.detail) }}</pre>
              </div>
              <div class="muted">工具：{{ String(entry.tool_id || '-') }} · 模式：{{ String(entry.approval_mode || '-') }} · {{ String(entry.created_at || '') }}</div>
            </div>
          </div>
          <div v-else class="muted">暂无审计记录（仅拦截/放行的不可逆动作会被记录）。</div>
        </div>

        <div v-if="toolRegistrySummary" class="muted">当前可用的受控工具：{{ toolRegistrySummary }}</div>
      </div>
    </section>
  </section>

  <!-- F4：首屏骨架。原先是空白 → 数据灌入的跳变，形状与真实内容对齐后不再跳 -->
  <section v-else class="page stack" aria-busy="true">
    <SkeletonBlock variant="card" :rows="2" label="正在加载任务信息…" />
    <SkeletonBlock variant="stat" :rows="5" label="正在加载漏洞统计…" />
    <SkeletonBlock variant="card" :rows="6" label="正在加载阶段数据…" />
    <SkeletonBlock variant="table" :rows="4" label="正在加载 findings…" />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { gsap } from "gsap";

import Breadcrumb from "@/components/Breadcrumb.vue";
import RoundReporter from "@/components/RoundReporter.vue";
import ReportDashboard from "@/components/ReportDashboard.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import FlowTypeSwitch from "@/components/FlowTypeSwitch.vue";
import StepFlow, { type StepFlowItem } from "@/components/StepFlow.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import { activeStage, eventLogs, stageLabel, stageName, stageStatusLabel, taskBadge, formatDuration, STAGE_HINTS, TASK_STAGE_ORDER, STAGE_CODES, type TaskStageKey } from "@/domain/task-view";
import { useTableScroll } from "@/domain/table-scroll";
import type { PipelineStage } from "@/types";
import { connectTaskSocket } from "@/services/ws";
import { useIastStore } from "@/stores/iast";
import { useWorkspaceStore } from "@/stores/workspaces";
import { http } from "@/services/http";
import type { Finding, IastCorrelationFinding, I2HypothesisOnlyDetail, I2PerHypothesis, ReportRecord, TaskEvent, TaintFlowHypothesis, TriggerSpecInfo } from "@/types";

const route = useRoute();
const router = useRouter();
const store = useWorkspaceStore();
const iastStore = useIastStore();
const selectedStageKey = ref<TaskStageKey>("preprocess");
const selectedResultStage = ref<"a1" | "a2" | "d2">("a1");
// 回退（2026-09-22）：tab 改为纯本地状态，不再与 URL 路径段同步。
// 理由：URL 路径段驱动的 tab 在纠偏重定向、书签、浏览器后退时容易丢失/错乱，
// 且 HITL 等内容不应依赖 URL 才能显示。tab 本质是「当前看哪一屏」的视图状态，留在组件内更稳。
// 深链/分享需求由其余页面入口承担，不强求 tab 进 URL。
type TaskTab = "Overview" | "Findings" | "Reports" | "HITL" | "Ops";
const selectedTab = ref<TaskTab>("Overview");
const reportLoading = ref(false);
const dashboardRoot = ref<HTMLElement | null>(null);
// D3：宽表横向滚动 + 首列冻结的状态同步（只给真溢出的表加冻结列阴影）
useTableScroll(dashboardRoot);
// 全局流量类型筛选（全部 / 业务逻辑 / 注入型），各面共享同一 lens；F7：记忆上次选择
const FLOW_FILTER_KEY = "sastai.flowFilter";
const _savedFlow = typeof localStorage !== "undefined" ? localStorage.getItem(FLOW_FILTER_KEY) : null;
const flowFilter = ref<"all" | "business_logic" | "injection" | "exposure">(
  _savedFlow === "business_logic" || _savedFlow === "injection" || _savedFlow === "exposure" ? _savedFlow : "all",
);
watch(flowFilter, (v) => {
  try {
    localStorage.setItem(FLOW_FILTER_KEY, v);
  } catch {
    /* 隐私模式下忽略 */
  }
});
const taskTabs = ["Overview", "Findings", "Reports", "HITL", "Ops"] as const;
function tabLabel(t: string): string {
  const m: Record<string, string> = { Overview: "总览", Findings: "发现", Reports: "报告", Logs: "日志", HITL: "人工介入", Ops: "运维 / 日志" };
  return m[t] || t;
}

// 单 task 运行时运维快照（2026-09-17 落地）：进程锁 / 进度心跳与卡死判定 / 端口可达性 /
// 最近事件流 / AI 调用。数据来自 GET /api/scan-tasks/{id}/runtime（后端 src/api/routers/tasks.py）。
// 与全局 /ops（跨任务运营度量）互补：这里只回答「这一个任务现在跑得怎么样」。
const runtime = ref<Record<string, any> | null>(null);
const runtimeError = ref("");
let runtimeTimer: number | null = null;
async function loadRuntime() {
  const id = Number(store.selectedTask?.id || 0);
  if (!id) return;
  try {
    const { data } = await http.get(`/api/scan-tasks/${id}/runtime`);
    runtime.value = data || null;
    runtimeError.value = "";
  } catch (err) {
    runtimeError.value = String(err);
  }
}
const runtimeProgressAge = computed(() => {
  const p = (runtime.value?.progress || {}) as Record<string, any>;
  if (!p.exists) return "无进度文件";
  const sec = Number(p.age_seconds || 0);
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.round(sec / 60)} 分钟前`;
  return `${(sec / 3600).toFixed(1)} 小时前`;
});
// 切到运维 tab 时立即拉一次并起 15 秒轮询；离开 tab 立刻停掉，避免无谓请求。
watch(
  () => selectedTab.value,
  (tab) => {
    if (tab === "Ops") {
      void loadRuntime();
      if (!runtimeTimer) runtimeTimer = window.setInterval(() => void loadRuntime(), 15000);
    } else if (runtimeTimer) {
      window.clearInterval(runtimeTimer);
      runtimeTimer = null;
    }
  },
  { immediate: true },
);
onUnmounted(() => {
  if (runtimeTimer) window.clearInterval(runtimeTimer);
  if (overviewTimer) window.clearInterval(overviewTimer);
});
let socket: WebSocket | null = null;
let lastPartialRefresh = 0;
let staleTimer: number | null = null;
let lastLiveEventAt = Date.now();

const stages = computed(() => buildUnifiedStages(store.selectedTask));
const breadcrumbItems = computed(() => {
  const items: Array<{ label: string; to?: string }> = [{ label: "工作区", to: "/" }];
  const ws = store.selectedWorkspace;
  const task = store.selectedTask;
  if (ws && task && ws.id === task.workspace_id) {
    items.push({ label: ws.name, to: `/workspaces/${ws.id}` });
  }
  if (task) items.push({ label: task.name });
  return items;
});
const activeStageValue = computed(() => stages.value.find((item) => item.key === selectedStageKey.value) || activeStage(store.selectedTask));

/**
 * 批次 4（2026-09-22）：把阶段数组映射成 StepFlow 的纯展示项。
 *
 * 为什么在这里映射而不是让组件自己算：进度比例依赖后端裁剪语义（items 被裁到 8 条时
 * 不能拿 items 算 done），耗时依赖 formatDuration 与本页的 started_at/finished_at 约定
 * —— 这些都是本页的知识，组件不该知道。组件只负责渲染，保持可单测。
 */
const stepItems = computed<StepFlowItem[]>(() => {
  const list = stages.value;
  return list.map((s, index) => ({
    key: s.key,
    label: s.label,
    code: stageCode(s.key),
    status: s.status,
    statusLabel: stageStatusLabel(s.status),
    progress: stageTaskProgress(s),
    // 只有运行中的阶段才显示已耗时：已完成阶段的耗时在阶段详情里给，不必挤进流程条
    elapsed: s.status === "running" ? stageElapsedLabel(s) : "",
    active: activeStageValue.value?.key === s.key,
    last: index === list.length - 1,
  }));
});

// A3：从 pipeline metrics 读取 #4② 已折叠的闭环轮次与 D2 验证轮次（纯前端消费，不改后端）
function stagePipelineMetrics(key: TaskStageKey): Record<string, unknown> {
  return (stages.value.find((s) => s.key === key)?.metrics || {}) as Record<string, unknown>;
}
const closedLoop = computed(() => {
  const m = stagePipelineMetrics("a2");
  const it = Number(m.closed_loop_iteration ?? 0);
  const mx = Number(m.closed_loop_max_iterations ?? 0);
  return { it, mx, pct: mx > 0 ? Math.min(100, Math.round((it / mx) * 100)) : 0 };
});
const d2Verify = computed(() => {
  const m = stagePipelineMetrics("d2");
  return { it: Number(m.d2_verify_iteration ?? 0), exploitable: Number(m.d2_verify_exploitable_count ?? 0) };
});
// C1/C2：阶段一句话释义 + 快照关键数字（耗时 + 主要指标）
function stageHint(key: string): string {
  return STAGE_HINTS[key as TaskStageKey] || "";
}
// severityTone 已收敛到 @/domain/task-view（批次 4，2026-09-22）
function stageSnapshotNums(s: { started_at?: string; finished_at?: string; metrics?: Record<string, unknown> }): string {
  const parts: string[] = [];
  const dur = formatDuration(s.started_at, s.finished_at);
  if (dur) parts.push(`耗时 ${dur}`);
  const skip = new Set(["closed_loop_iteration", "closed_loop_max_iterations", "d2_verify_iteration", "d2_verify_exploitable_count", "status"]);
  for (const [k, v] of Object.entries((s.metrics || {}) as Record<string, unknown>)) {
    if (skip.has(k) || v === "" || v === null || v === undefined) continue;
    parts.push(`${humanizeKey(k)} ${fmtVal(v)}`);
    if (parts.length >= 3) break;
  }
  return parts.length ? parts.join(" · ") : "—";
}

/**
 * 阶段对象的宽松视图。
 * stages 与 activeStageValue 的来源不同（后者回退到 task-view.activeStage 的返回，
 * 不含 tasks 字段），若参数类型只声明 tasks 这一个可选属性，TS 的弱类型检查会以
 * 「无共同属性」报错。这里带上监控化实际用到的全部字段，两处形态都能传入，
 * 缺 tasks 时自然降级为 0 / 空列表。
 */
type StageLike =
  | {
      status?: string;
      started_at?: string;
      finished_at?: string;
      tasks?: { total?: number; items?: { name?: string; status?: string; detail?: string }[] } | null;
    }
  | null
  | undefined;

function stageTaskTotal(s: StageLike): number {
  return Number((s as any)?.tasks?.total || 0);
}
function stageTaskItems(s: StageLike): { name?: string; status?: string; detail?: string }[] {
  return ((s as any)?.tasks?.items || []) as { name?: string; status?: string; detail?: string }[];
}

// ---- 2.2 监控化（2026-09-19 落地）------------------------------------------------

/** 流程节点徽标用的任务进度。后端 items 被裁剪到 8 条，裁剪时不能拿 items 算比例。 */
function stageTaskProgress(s: StageLike): { done: number; total: number; showRatio: boolean } {
  const items = stageTaskItems(s);
  const total = stageTaskTotal(s);
  const done = items.filter((it) => String(it?.status || "") === "completed").length;
  return { done, total, showRatio: total > 0 && items.length >= total };
}

function formatMs(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  if (h) return `${h}h${m}m`;
  if (m) return `${m}m${sec}s`;
  return `${sec}s`;
}

/** 阶段已耗时：已结束取 started→finished，运行中取 started→now（formatDuration 内部按 now 计）。 */
function stageElapsedLabel(s: StageLike): string {
  return formatDuration(String((s as any)?.started_at || ""), String((s as any)?.finished_at || "")) || "—";
}

/**
 * D1 预计剩余（估算）：以本轮已结束阶段的耗时均值为先验，减去当前阶段已耗时。
 * 跨任务历史均值当前无数据源，故明确只按本轮估算并在 UI 标注「估算」；
 * 无已结束阶段作参照、或已超过均值时返回空，不给「即将完成」的假承诺。
 */
function stageEtaLabel(s: StageLike): string {
  if (String((s as any)?.status || "") !== "running") return "";
  const started = String((s as any)?.started_at || "");
  if (!started) return "";
  const start = Date.parse(started);
  if (Number.isNaN(start)) return "";
  const elapsedMs = Date.now() - start;
  if (elapsedMs < 0) return "";
  const durations = stages.value
    .filter((x) => x.started_at && x.finished_at)
    .map((x) => Date.parse(String(x.finished_at)) - Date.parse(String(x.started_at)))
    .filter((d) => Number.isFinite(d) && d > 0);
  if (!durations.length) return "";
  const mean = durations.reduce((a, b) => a + b, 0) / durations.length;
  const remainMs = mean - elapsedMs;
  if (remainMs <= 0) return "";
  return formatMs(remainMs);
}

// 手动点击流程节点的时间戳：10 秒内轮询不抢焦点，避免用户正在看某阶段时被跳走。
let manualStageFocusAt = 0;
function selectStage(key: TaskStageKey): void {
  selectedStageKey.value = key;
  manualStageFocusAt = Date.now();
}

// Overview tab 在运行中任务上的 15s 粗粒度轮询（复刻 /ops 运维轮询写法）。
// 终态任务不轮询，保持静态展示，避免无谓请求。
let overviewTimer: number | null = null;
async function refreshOverview(): Promise<void> {
  const id = Number(store.selectedTask?.id || 0);
  if (!id) return;
  try {
    await store.fetchTask(id);
    const current = String(store.selectedTask?.summary?.current_stage || "");
    if (current && Date.now() - manualStageFocusAt > 10000) {
      selectedStageKey.value = current as TaskStageKey;
    }
  } catch {
    // 轮询失败静默处理，下一轮再试，不打断用户查看
  }
}

function buildUnifiedStages(task: typeof store.selectedTask) {
  // 任务数据尚未加载（或仍为上一个任务的残留）时，统一显示「加载中…」，
  // 避免阶段状态闪现成「跳过 / 未开始」误导用户。
  if (!task?.summary) {
    return TASK_STAGE_ORDER.map((key) => ({
      key,
      label: stageName(key),
      status: "loading" as const,
      message: "",
      metrics: {},
      started_at: "",
      finished_at: "",
      active: false,
      tasks: { total: 0, items: [] } as PipelineStage["tasks"],
    }));
  }
  const pipeline = (task?.summary?.pipeline || {}) as Record<string, PipelineStage>;
  return TASK_STAGE_ORDER.map((key) => {
    // i1/d2/i2 的状态必须以 task 自身 pipeline 为唯一真值（与后端 i1→d1、i2→d2 派生一致），
    // 否则会被全局 iastStore（按 workspace 维度、且 iast_events.task_id 全为 NULL 导致回退全量）带飞，
    // 出现「I1/I2 显示完成、D1/D2 显示未开始」的错乱。iastStore 仅用于丰富文案与指标，绝不覆盖状态。
    if (key === "i1" || key === "d2" || key === "i2") {
      const p = pipeline[key] || {};
      let baseStatus = p.status || "pending";
      const isSkipped = baseStatus === "skipped";
      const isActive = baseStatus === "completed" || baseStatus === "running" || baseStatus === "failed";
      let message = p.message || "";
      let metrics = p.metrics || {};
      if (key === "i1") {
        const iastObs = iastStore.correlation?.stats?.iast_observed ?? 0;
        const iastTotal = iastStore.correlation?.stats?.total_hypotheses ?? iastStore.correlation?.findings?.length ?? 0;
        if (!message && isActive) {
          message = `IAST 已观测 ${iastObs} 条运行时关联（SAST 假说 ${iastTotal} 条）`;
        }
        if (!message) message = isSkipped ? "未启用" : "等待 IAST 运行时事件";
        if (isActive && Object.keys(metrics).length === 0) {
          metrics = iastStore.correlation?.stats || {};
        }
      } else if (key === "d2") {
        const count = (iastStore.adjudication?.per_hypothesis || []).length;
        if (!message && isActive) {
          message = count ? `已校验 ${count} 条 SAST 假说` : "D2 校验进行中";
        }
        if (!message) message = isSkipped ? "未启用" : "等待 SAST 假说与运行时观测对齐";
        if (isActive && Object.keys(metrics).length === 0) {
          metrics = count ? { hypothesis_count: count } : {};
        }
      } else {
        // i2
        // 2026-09-28：闭环异常必须在阶段卡上标红。此前后端 status 恒为 completed，
        // 闭环崩溃在界面上完全不可见（run 25 事故：异常被 benchmark_cli 的 except 吞掉，
        // 第二轮 D2 重验与 spec 回灌静默丢失，现象却显示为「闭环跑完、无需动作」）。
        // 后端已把 stage_results.i2.status 置 failed 并写入 closed_loop.error，这里兜底读取。
        const i2Stage = (task?.summary?.stage_results as Record<string, any> | undefined)?.i2 as
          | Record<string, any>
          | undefined;
        const clErr = String(i2Stage?.closed_loop?.error || i2Stage?.error || "");
        if (clErr) {
          baseStatus = "failed";
          message = `闭环执行失败：${clErr}（第二轮 D2 重验与 spec 回灌未执行）`;
        }
        const hasAdj = Boolean(iastStore.adjudication?.stats || iastStore.adjudication?.per_hypothesis?.length);
        if (!message && isActive) {
          message = hasAdj ? "已生成覆盖率差集" : "I2 裁决进行中";
        }
        if (!message) message = isSkipped ? "未启用" : "等待 D2 校验结果";
        if (isActive && Object.keys(metrics).length === 0) {
          metrics = iastStore.adjudication?.stats || {};
        }
      }
      return {
        key,
        label: stageName(key),
        status: baseStatus,
        message,
        metrics,
        started_at: p.started_at || "",
        finished_at: p.finished_at || "",
        active: (task?.summary?.current_stage || task?.phase) === key,
        // 2026-09-17：阶段 -> 具体任务清单（后端 pipeline_view 产出，替代空壳卡片）。
        tasks: p.tasks || { total: 0, items: [] },
      };
    }
    const p = pipeline[key] || {};
    return {
      key,
      label: stageName(key),
      status: p.status || "pending",
      message: p.message || "",
      metrics: p.metrics || {},
      started_at: p.started_at || "",
      finished_at: p.finished_at || "",
      active: (task?.summary?.current_stage || task?.phase) === key,
      // 2026-09-17：阶段 -> 具体任务清单（后端 pipeline_view 产出，替代空壳卡片）。
      tasks: p.tasks || { total: 0, items: [] },
    };
  });
}
const failedStage = computed(() => stages.value.find((item) => item.status === "failed") || null);
const logs = computed(() => eventLogs(store.events));
const iastStats = computed(() => iastStore.correlation?.stats || ({} as Record<string, unknown>));
const iastFindings = computed<IastCorrelationFinding[]>(() => iastStore.correlation?.findings || []);
const iastAdjudication = computed(() => iastStore.adjudication);
const iastAdjudicationStats = computed(() => iastAdjudication.value?.stats || ({} as Record<string, unknown>));
const iastListener = computed(() => iastStore.taskEventsSummary as Record<string, any> | null);
const iastDiagnostics = computed(() => (iastStore.correlation as any)?.diagnostics as Record<string, any> | null);
const d1Specs = computed<TriggerSpecInfo[]>(() => iastStore.triggerSpecs as TriggerSpecInfo[]);
// Q4：D2 逐漏洞证据链 + 按族分布，来自 summary.stage_results.d2（后端 _aggregate_d2_verdict 回填）。
const d2Stage = computed<Record<string, any>>(() => {
  const summary = store.selectedTask?.summary as Record<string, any> | undefined;
  const sr = (summary?.stage_results as Record<string, any> | undefined) || {};
  const results = (summary?.results as Record<string, any> | undefined) || {};
  const pipeline = (summary?.pipeline as Record<string, any> | undefined) || {};
  return sr.d2 || results.d2 || pipeline.d2 || {};
});
const d2Details = computed<Array<Record<string, any>>>(() => {
  const v = d2Stage.value.verifications_detail;
  return Array.isArray(v) ? v : [];
});
const d2ByFamily = computed<Record<string, number>>(() => {
  const f = d2Stage.value.by_family;
  return (f && typeof f === "object") ? f : {};
});
// #2C A2 漏斗：A2 产出总数 → 可解析(已登记 TriggerSpec) → 未解析(原因)。
// 取自 stage_results.a2_poc；历史任务该键不存在，兜底到 results.a2_poc（同一份数据）。
const a2Funnel = computed(() => {
  const summary = store.selectedTask?.summary as Record<string, any> | undefined;
  const sr = (summary?.stage_results as Record<string, any> | undefined) || {};
  const results = (summary?.results as Record<string, any> | undefined) || {};
  return (sr.a2_poc as Record<string, any> | undefined)
      || (results.a2_poc as Record<string, any> | undefined) || null;
});
// #Q4 AP 攻击计划：A2→D1 之间的 POC 投影，来自 stage_results.attack_plan；兜底到 results.attack_plan 与 pipeline.attack_plan。
const attackPlan = computed(() => {
  const summary = store.selectedTask?.summary as Record<string, any> | undefined;
  const sr = (summary?.stage_results as Record<string, any> | undefined) || {};
  const results = (summary?.results as Record<string, any> | undefined) || {};
  const p = (summary?.pipeline as Record<string, any> | undefined)?.attack_plan;
  const ap = (sr.attack_plan as Record<string, any> | undefined)
      || (results.attack_plan as Record<string, any> | undefined)
      || (p as Record<string, any> | undefined) || {};
  // 兼容两种存储形态：优先 ap.metrics（pipeline 形态），否则回退到 top-level（results 形态）。
  const metrics = (ap.metrics as Record<string, any> | undefined) || {};
  const resolved = ((metrics.plan_count !== undefined) || ((metrics.entries as unknown[])?.length))
      ? metrics
      : ap;
  return ((resolved.plan_count !== undefined) || ((resolved.entries as unknown[])?.length))
      ? (resolved as Record<string, any>) : null;
});
// Q4 运行时命中回填：D1/D2 重放后按 canary 身份段反查 IAST 事件得到的命中态徽章
function runtimeBadgeClass(s?: string): string {
  if (s === 'arrived') return 'badge-success';          // 已触达 sink
  if (s === 'business_confirmed') return 'badge-success'; // 业务差分重放 + D2 确认可利用（最高置信）
  if (s === 'd2_confirmed') return 'badge-info';        // D2 已裁决但未触达 sink
  if (s === 'observed') return 'badge-warning';         // 观测到 canary 但未触达 sink
  if (s === 'not_hit') return 'badge-danger';           // 未命中
  return 'badge-muted';                                 // 未回填（旧任务）
}
function runtimeLabel(s?: string): string {
  if (s === 'arrived') return '已命中 sink';
  if (s === 'business_confirmed') return '业务差分确认';
  if (s === 'd2_confirmed') return 'D2 已裁决';
  if (s === 'observed') return '已观测到';
  if (s === 'not_hit') return '未命中';
  return '—';
}
// 漏洞族中文名（复用 FAMILY_ZH，兼容连字符写法如 path-traversal）
function familyLabel(fam?: string): string {
  if (!fam) return '—';
  const key = fam.toLowerCase();
  return FAMILY_ZH[key] || FAMILY_ZH[key.replace(/-/g, ' ')] || fam;
}
// 探针 canary 身份段属内部标识，普通用户无需看完整 token，仅展示截断形态
function maskCanary(c?: string | null): string {
  if (!c) return '无';
  return c.length > 12 ? c.slice(0, 10) + '…' : c;
}
// POC 预览：尝试 base64 解码（攻击载荷常以 base64 存储，如 XSS），失败则原样展示并截断
function decodePoc(preview?: string | null): string {
  if (!preview) return '—';
  const trimmed = preview.trim();
  if (/^[A-Za-z0-9+/=_-]{8,}$/.test(trimmed)) {
    try {
      const bin = atob(trimmed.replace(/-/g, '+').replace(/_/g, '/'));
      if (bin && /[\x20-\x7e]/.test(bin)) return bin.length > 140 ? bin.slice(0, 140) + '…' : bin;
    } catch {
      /* 非 base64，按原样返回 */
    }
  }
  return trimmed.length > 140 ? trimmed.slice(0, 140) + '…' : trimmed;
}
const iastHypothesisMap = computed(() => {
  const map = new Map<string, I2PerHypothesis>();
  for (const h of iastAdjudication.value?.per_hypothesis || []) map.set(h.vulnerability_hash_v2, h);
  return map;
});
const iastStabilityMap = computed(() => {
  const map = new Map<string, I2HypothesisOnlyDetail>();
  for (const d of iastAdjudication.value?.hypothesis_only_detail || []) map.set(d.vulnerability_hash_v2, d);
  return map;
});
const reportSummary = computed(() => (store.selectedTask?.summary?.final_report_summary || {}) as Record<string, unknown>);
const hitlSettings = computed(() => store.hitlSettings);
const pendingActionsCount = computed(() => Number(hitlSettings.value?.pending_actions?.length || 0));
const pendingActions = computed(() => Array.isArray(hitlSettings.value?.pending_actions) ? hitlSettings.value!.pending_actions : []);
// ⑤：批量裁决选择集 + 审计轨迹 + 挂起可用性
const selectedActionIds = ref<string[]>([]);
const allSelected = computed(
  () => pendingActions.value.length > 0 && selectedActionIds.value.length === pendingActions.value.length,
);
const hitlAudit = computed(() => store.hitlAudit);
const canSuspend = computed(() => {
  const status = String(store.selectedTask?.status || "");
  return status !== "running" && status !== "suspended";
});
const scaFindings = computed(() => store.findings.filter((finding) => isScaFinding(finding)));
// 2026-09-18（A2 方案二）：聚合吸收成员补行。它们有独立 findings 行（供覆盖率统计与关联桥），
// 但不是独立漏洞 —— 证据已并入所属聚合 finding，故不计入「应用层漏洞」、默认也不在列表中重复展示。
const absorbedFindings = computed(() => store.findings.filter((finding) => isAbsorbedFinding(finding)));
// A4（方案二）：运行期判定。status=running 时顶部切分轴计数口径（findings 表此时恒空）。
const isTaskRunning = computed(() => String(store.selectedTask?.status || "").toLowerCase() === "running");

// 2.2 监控化：Overview tab 且任务运行中 -> 15s 粗粒度轮询；离 tab 或任务进入终态立即停掉，
// 终态任务保持静态展示，不发无谓请求。
// 注意：本 watch 带 immediate，必须定义在 isTaskRunning 之后，否则引用会踩 TDZ。
watch(
  () => [selectedTab.value, isTaskRunning.value] as const,
  ([tab, running]) => {
    if (tab === "Overview" && running) {
      void refreshOverview();
      if (!overviewTimer) overviewTimer = window.setInterval(() => void refreshOverview(), 15000);
    } else if (overviewTimer) {
      window.clearInterval(overviewTimer);
      overviewTimer = null;
    }
  },
  { immediate: true },
);
// D2：应用层漏洞 = 合计 - SCA 组件漏洞 - 聚合吸收成员（口径透明，避免「总漏洞」含义歧义与双计）
const totalFindings = computed(() =>
  Number(store.selectedTask?.summary?.finding_count || store.findings.length || 0),
);
const appLayerCount = computed(() =>
  Math.max(0, totalFindings.value - scaFindings.value.length - absorbedFindings.value.length),
);
// D4：占比条只用真实计数，四舍五入到整数；两边都取整后由 CSS 保证拼满 100%
const appSharePct = computed(() => {
  if (!totalFindings.value) return 100;
  return Math.round((appLayerCount.value / totalFindings.value) * 100);
});
// P2-4（2026-09-13）：SCA 组件漏洞默认不混入应用层 findings 列表（总数口径同步改为
// canonical，见 benchmark_cli 汇总）。此处提供开关，默认关闭。
const showScaFindings = ref(false);
// 2026-09-18（A2 方案二）：聚合吸收成员默认折叠，与 SCA 开关同一交互范式。
const showAbsorbedFindings = ref(false);
function isScaFinding(finding: { raw?: Record<string, unknown> | null; finding_type?: string }): boolean {
  const raw = (finding.raw || {}) as Record<string, unknown>;
  const text = String(raw.display_family || finding.finding_type || raw.type || "").toLowerCase();
  return text.includes("sca") || Boolean(raw.sca) || String(raw.source || "").toLowerCase() === "sca";
}
// 2026-09-18（A2 方案二）：聚合吸收成员判定。
// 后端在聚合时为被吸收节点补一行，raw.is_absorbed=true 且 raw.absorbed_by_group_key 指向所属
// 聚合组（见 a2_intelligent_agent._merge_chain_vulnerabilities）。兼容落盘的布尔/字符串两种形态。
function isAbsorbedFinding(finding: { raw?: Record<string, unknown> | null }): boolean {
  const raw = (finding.raw || {}) as Record<string, unknown>;
  const flag = raw.is_absorbed;
  if (typeof flag === "string") return ["1", "true", "yes"].includes(flag.trim().toLowerCase());
  return Boolean(flag);
}
// A4：运行期分轴计数的第二取数口。A1/A2 的 finding_count 落在 summary.pipeline.<stage>.metrics，
// 与 results.<stage>.* 不是同一容器（results 在运行期也不落数），故单独取值。
function pipelineMetric(stageName: string, metric: string) {
  const pipeline = (store.selectedTask?.summary?.pipeline || {}) as Record<string, unknown>;
  const stage = (pipeline[stageName] || {}) as Record<string, unknown>;
  const metrics = (stage.metrics || {}) as Record<string, unknown>;
  return String(metrics[metric] ?? 0);
}
const reviewMetrics = computed(() => store.reviewMetrics || {});
const entryRows = computed(() => {
  const rows = (store.entryDiscovery?.entries || []) as Record<string, unknown>[];
  return Array.isArray(rows) ? rows.slice(0, 80) : [];
});
const entryCount = computed(() => Number(store.entryDiscovery?.entry_count || stageMetric("entry_discovery", "entry_count") || 0));
const entryRuleCount = computed(() => Number(((store.entryDiscovery?.rule_candidates as unknown[]) || []).length || stageMetric("entry_discovery", "rule_candidate_count") || 0));
const toolRegistrySummary = computed(() => {
  if (!store.toolRegistry.length) return "";
  return store.toolRegistry.map((item) => item.id).slice(0, 8).join(", ");
});
const approvalModeDraft = ref("off");
const allowlistDraft = ref("");
const stageResultTabs = [
  { key: "a1" as const, label: "A1" },
  { key: "a2" as const, label: "A2" },
  { key: "d2" as const, label: "D2" },
];
const d2CandidateCount = computed(() => {
  const reported = Number(reportSummary.value.d2_candidate_count || 0);
  if (reported > 0) return reported;
  return store.findings.filter((finding) => isProjectDeserializationChain(finding)).length;
});
const sortedFindings = computed(() =>
  [...store.findings]
    // P2-4：默认隐藏 SCA 组件漏洞（应用层 canonical 口径），开关打开时才显示。
    .filter((finding) => showScaFindings.value || !isScaFinding(finding))
    // 2026-09-18（A2 方案二）：默认隐藏聚合吸收成员，避免与所属聚合 finding 重复展示；
    // 开关打开时显示，并在行内标注归属的聚合组。
    .filter((finding) => showAbsorbedFindings.value || !isAbsorbedFinding(finding))
    .sort((left, right) => {
      const leftPriority = Number((left.raw?.priority_score as number) || 0);
      const rightPriority = Number((right.raw?.priority_score as number) || 0);
      if (rightPriority !== leftPriority) return rightPriority - leftPriority;
      return Number((right.raw?.supporting_node_count as number) || 0) - Number((left.raw?.supporting_node_count as number) || 0);
    }),
);
const selectedStageFindings = computed(() => findingsForStage(selectedResultStage.value));
// 流量类型切换：按 flowFilter 过滤各面列表（优先后端 flow_type；缺失时前端重算）
const hashFlowMap = computed<Record<string, string>>(() => {
  const m: Record<string, string> = {};
  for (const f of store.findings) {
    const ft = (f.raw as any)?.flow_type;
    const h = (f.raw as any)?.vulnerability_hash_v2;
    if (ft && h) m[h] = ft;
  }
  return m;
});
function filterByFlow<T>(list: T[], kind?: "finding" | "ap" | "d1" | "d2" | "i2"): T[] {
  if (flowFilter.value === "all") return list;
  return list.filter((it) => flowTypeOf(it as any, kind) === flowFilter.value);
}
const visibleFindings = computed(() => filterByFlow(sortedFindings.value, "finding"));
const visibleStageFindings = computed(() => filterByFlow(selectedStageFindings.value, "finding"));
const visibleApEntries = computed(() => filterByFlow((attackPlan.value?.entries as any[]) || [], "ap"));
const visibleD1Specs = computed(() => filterByFlow(d1Specs.value as any[], "d1"));
const visibleD2Details = computed(() => filterByFlow(d2Details.value as any[], "d2"));
const visibleI2Findings = computed(() => filterByFlow(iastFindings.value as any[], "i2"));
const visibleUnresolved = computed(() => {
  const list = (a2Funnel.value?.unresolved_reasons as any[]) || [];
  if (flowFilter.value === "all") return list;
  return list.filter((x) => (hashFlowMap.value[x.vulnerability_hash_v2] || "injection") === flowFilter.value);
});
const visibleUnmatched = computed(() => {
  const list = (iastDiagnostics.value?.unmatched_canary_events as any[]) || [];
  if (flowFilter.value === "all") return list;
  return list.filter((x) => (hashFlowMap.value[x.vulnerability_hash_v2] || "injection") === flowFilter.value);
});
// 各面切换计数（基于未过滤列表）
const findingsFlowCounts = computed(() => countsFor(sortedFindings.value, "finding"));
const apFlowCounts = computed(() => countsFor((attackPlan.value?.entries as any[]) || [], "ap"));
const d1FlowCounts = computed(() => countsFor(d1Specs.value as any[], "d1"));
const d2FlowCounts = computed(() => countsFor(d2Details.value as any[], "d2"));
const i2FlowCounts = computed(() => countsFor(iastFindings.value as any[], "i2"));
const unresolvedFlowCounts = computed(() => {
  const list = (a2Funnel.value?.unresolved_reasons as any[]) || [];
  const c: { all: number; business_logic: number; injection: number; exposure: number } = { all: list.length, business_logic: 0, injection: 0, exposure: 0 };
  for (const x of list) {
    const k = (hashFlowMap.value[x.vulnerability_hash_v2] || "injection") as "business_logic" | "injection" | "exposure";
    c[k] += 1;
  }
  return c;
});
const emptyStageResultText = computed(() =>
  selectedResultStage.value === "d2"
    ? "No dynamic verification results are ready for this stage yet."
    : "No findings are stored for this stage yet.",
);

onMounted(async () => {
  // #3：URL 同时支持 /workspace/:slug/task/:taskId 与旧 /tasks/:id，优先取 slug 路由的 taskId。
  const rawTaskId = route.params.taskId ?? route.params.id;
  const taskId = Number(rawTaskId);
  try {
    await Promise.all([
      store.fetchTask(taskId),
      store.fetchTaskEvents(taskId),
      store.fetchTaskFindings(taskId),
      store.fetchTaskReports(taskId),
      store.fetchTaskHitl(taskId),
      store.fetchTaskHitlAudit(taskId),
      store.fetchToolRegistry(),
      store.fetchScaTools(),
      store.fetchReviewMetrics(taskId),
    ]);
  } catch (error: any) {
    const status = Number(error?.response?.status || 0);
    if (status === 404) {
      store.selectedTask = null;
      await router.replace("/");
      return;
    }
    throw error;
  }
  // #3：把页面 workspace 上下文对齐到本 task 真正所属的工作区，避免跨工作区混淆；
  // 若 URL 里的 slug 与实际工作区 slug 不符，静默重定向到正确 URL（书签/手输旧链接时纠偏）。
  const wsId = store.selectedTask?.workspace_id;
  if (wsId) {
    try {
      await store.fetchWorkspace(Number(wsId));
    } catch {
      /* 工作区拉取失败不阻断任务页 */
    }
    const correctSlug = store.selectedWorkspace?.slug;
    const urlSlug = route.params.slug;
    if (correctSlug && urlSlug && correctSlug !== urlSlug) {
      // 回退：tab 已不再进 URL，纠偏直接跳到正确 slug，不拼 tab 段（避免静默跳回 Overview）。
      await router.replace(`/workspace/${correctSlug}/task/${taskId}`);
    }
  }
  selectedStageKey.value = (store.selectedTask?.summary?.current_stage as TaskStageKey) || "preprocess";
  approvalModeDraft.value = String(hitlSettings.value?.approval_mode || "off");
  allowlistDraft.value = Array.isArray(hitlSettings.value?.tool_allowlist) ? hitlSettings.value!.tool_allowlist.join(", ") : "";
  await loadPreferredReport();
  loadIastCorrelation().catch(() => {});
  // #2D：拉取本 task 的 D1 重放靶面（TriggerSpec 明细）。
  if (wsId) {
    iastStore.fetchTriggerSpecs({ task_id: taskId, workspace_id: Number(wsId) }).catch(() => {});
  }
  animateDashboard();
  startStaleWatcher(taskId);
  socket = connectTaskSocket(taskId, async (event) => {
    lastLiveEventAt = Date.now();
    if (event.event_type === "heartbeat") return;
    store.pushEvent(event);
    if (event.event_type === "task_completed" || event.event_type === "task_failed") {
      try {
        await Promise.all([store.fetchTask(taskId), store.fetchTaskFindings(taskId), store.fetchTaskReports(taskId), store.fetchTaskHitl(taskId), store.fetchTaskHitlAudit(taskId)]);
      } catch (error: any) {
        const status = Number(error?.response?.status || 0);
        if (status === 404) {
          store.selectedTask = null;
          socket?.close();
          await router.replace("/");
          return;
        }
        throw error;
      }
      await loadPreferredReport();
      return;
    }
    if (event.event_type === "task_progress" || event.event_type === "task_hitl_pending" || event.event_type === "task_hitl_resolved") {
      await maybeRefreshArtifacts(taskId, event);
    }
  });
});

onUnmounted(() => {
  socket?.close();
  if (staleTimer) window.clearInterval(staleTimer);
});

watch(
  () => store.selectedTask?.summary?.current_stage,
  (value) => {
    // 2.2：活跃阶段跟随，但用户 10s 内手动点过节点则不抢焦点（websocket 每秒推送，
    // 若不设宽限，用户点开某阶段会被立刻跳回当前阶段）。
    if (value && Date.now() - manualStageFocusAt > 10000) {
      selectedStageKey.value = value as TaskStageKey;
    }
  },
);

watch(selectedTab, (tab) => {
  animateDashboard();
  if (tab === "HITL") void refreshAudit();
});

watch(stages, () => animateDashboard(), { deep: true });

watch(
  () => hitlSettings.value,
  (value) => {
    approvalModeDraft.value = String(value?.approval_mode || "off");
    allowlistDraft.value = Array.isArray(value?.tool_allowlist) ? value!.tool_allowlist.join(", ") : "";
  },
  { deep: true },
);

function metricEntries(metrics: Record<string, unknown> | undefined) {
  return Object.entries(metrics || {}).filter(([, value]) => value !== "" && value !== null && value !== undefined);
}

// 指标值可能是对象/数组（如 by_family、fixed_versions）。直接 String() 会渲染成
// 「[object Object]」，这里按类型展开成可读文本，且只做展示、不改数值。
function fmtVal(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) {
    if (!value.length) return "0 项";
    const simple = value.every((x) => typeof x === "string" || typeof x === "number");
    if (!simple) return `${value.length} 项`;
    const head = value.slice(0, 3).join("/");
    return value.length > 3 ? `${head} …共 ${value.length} 项` : head;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (!entries.length) return "空";
    const head = entries
      .slice(0, 4)
      .map(([k, v]) => `${k} ${Array.isArray(v) ? `${v.length} 项` : typeof v === "object" && v !== null ? "…" : String(v)}`)
      .join(" / ");
    return entries.length > 4 ? `${head} …共 ${entries.length} 项` : head;
  }
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
}

function humanizeKey(key: string) {
  const labels: Record<string, string> = {
    finding_count: "Findings",
    verified_count: "Verified",
    exploitable_count: "Exploitable",
    verified_poc_count: "Verified POC",
    poc_generated_count: "POC generated",
    report_count: "Reports",
    ai_review_total: "AI reviewed",
    auto_close_candidates: "Auto-close candidates",
    noise_reduction_simulated: "Noise reduction",
    entry_count: "Entries",
    rule_candidate_count: "Rule candidates",
    sca_count: "SCA findings",
  };
  return labels[key] || humanizeUnmapped(key);
}

/**
 * D6（2026-09-19）：未映射键的兜底——下划线拆词 + 驼峰拆词，逐词首字母大写。
 * 后端指标键混用 snake_case 与 camelCase（如 model_profile / modelProfile），
 * 此前只按下划线切分，camelCase 键会原样连排成一坨读不出来；
 * 已在映射表里的键走上面的 Title Case，与映射表风格对齐。
 */
function humanizeUnmapped(key: string): string {
  const spaced = String(key || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")      // modelProfile -> model Profile
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")   // HTTPStatus -> HTTP Status
    .replace(/[_.]+/g, " ")                       // snake_case / 点号 -> 空格
    .replace(/\s+/g, " ")
    .trim();
  if (!spaced) return "";
  // 已是全大写的缩写词（HTTP / SQL 等）保持原样，其余逐词首字母大写
  return spaced
    .split(" ")
    .map((word) => (/^[A-Z0-9]+$/.test(word) ? word : capitalize(word)))
    .join(" ");
}

function capitalize(text: string) {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

function stageMetric(stageName: string, metric: string) {
  return String(((store.selectedTask?.summary?.results || {}) as any)?.[stageName]?.[metric] ?? 0);
}

function stageSummary(stageName: string) {
  const result = (((store.selectedTask?.summary?.results || {}) as any)?.[stageName] || {}) as Record<string, unknown>;
  if (stageName === "preprocess") return `代码索引完成：函数 ${String(result.indexed_functions ?? 0)} 个、HTTP 入口 ${String(result.http_entries ?? 0)} 个`;
  if (stageName === "a1") return `A1 发现 ${String(result.finding_count ?? 0)} 条结果`;
  if (stageName === "a2") return `A2 发现 ${String(result.finding_count ?? 0)} 条结果`;
  if (stageName === "d2") {
    return `D2 已验证 ${String(result.verified_count ?? 0)}、可利用 ${String(result.exploitable_count ?? 0)}、候选 ${d2CandidateCount.value}`;
  }
  if (stageName === "sca") return `SCA 发现 ${String(result.finding_count ?? scaFindings.value.length)} 个组件漏洞`;
  if (stageName === "entry_discovery") return `入口 ${String(result.entry_count ?? 0)} 个，规则候选 ${String(result.rule_candidate_count ?? 0)} 条`;
  if (stageName === "ai_review") return `AI 复核 ${String(result.ai_review_total ?? 0)} 条，灰度候选 ${String(result.auto_close_candidates ?? 0)} 条`;
  if (stageName === "d1") {
    const msg = String(result.message || "");
    if (msg) return msg;
    const candidate = Number(result.candidate_count ?? 0);
    const finding = Number(result.finding_count ?? 0);
    if (candidate || finding) return `A2→D1 自动重放：${candidate} 条 TriggerSpec，${finding} 条 DAST impact`;
    return "D1 操作器资产重放完成";
  }
  if (stageName === "reporting") return `已生成 ${String(result.report_count ?? store.reports.length)} 份报告`;
  const keys = Object.keys(result);
  if (!keys.length) return "该阶段尚未产生运行明细。";
  return keys.slice(0, 4).map((k) => `${humanizeKey(k)}: ${fmtVal(result[k])}`).join("，");
}

function stageCode(key: string): string {
  return STAGE_CODES[key as TaskStageKey] || key.toUpperCase().replace("_", ".");
}

function stageMessage(stage: { key: string; message?: string }): string {
  if (stage?.message) return stage.message;
  return stageSummary(stage.key);
}

const activeStageDetail = computed(() => {
  const stage = activeStageValue.value;
  if (!stage) return "等待阶段产出";
  return stage.message || stageSummary(stage.key);
});

function hashLabel(finding: Finding) {
  return String(finding.raw?.vulnerability_hash_v2 || finding.raw?.chain_id || finding.raw?.canonical_group_key || "-").slice(0, 24);
}

function aiReviewStatus(finding: Finding) {
  const review = finding.raw?.ai_review || {};
  const verdict = String(review.ai_verdict || "pending");
  const confidence = String(review.confidence || "");
  const auto = review.auto_close_candidate ? " · gray auto-close candidate" : "";
  return `${verdict}${confidence ? ` (${confidence})` : ""}${auto}`;
}

function fixSummary(finding: Finding) {
  return String(finding.raw?.fix_suggestion?.summary || finding.raw?.fix || "");
}

function scaFixText(finding: Finding) {
  const versions = finding.raw?.sca?.fixed_versions;
  return Array.isArray(versions) && versions.length ? `Upgrade to ${versions.join(", ")}` : String(finding.raw?.fix || "Review advisory");
}

// ---- Q1：SCA 取证徽章（交叉验证 / 版本核查 / 置信度）----
// 三态区分：字段缺失 = 未核查（灰），不可与「已核查但受影响」混为一谈。
function scaMeta(finding: Finding): Record<string, any> {
  return (finding.raw?.sca || {}) as Record<string, any>;
}
function scaVersionBadge(finding: Finding): { label: string; tone: string; detail: string } {
  const meta = scaMeta(finding);
  const flag = meta.not_affected;
  if (flag === true) {
    return {
      label: "已修复 / 不受影响",
      tone: "badge-success",
      detail: `实际版本 ${String(meta.component_version || "")} ≥ fixed 版本 ${String((meta.fixed_versions || []).join(", "))}，疑似误报`,
    };
  }
  if (flag === false) {
    return {
      label: "受影响",
      tone: "badge-danger",
      detail: `实际版本 ${String(meta.component_version || "")} 低于 fixed 版本 ${String((meta.fixed_versions || []).join(", "))}`,
    };
  }
  return { label: "未核查", tone: "badge-muted", detail: "本次扫描未执行版本比对（旧任务或富集未生效）" };
}
function scaCrossBadge(finding: Finding): { label: string; tone: string; detail: string } {
  const meta = scaMeta(finding);
  const flag = meta.cross_validated;
  const tools = (meta.detected_by || [meta.source_tool]).filter(Boolean);
  if (flag === true) {
    return { label: "多工具确认", tone: "badge-success", detail: `被 ${tools.join("、")} 共同报出` };
  }
  if (flag === false) {
    return { label: "单工具", tone: "badge-warning", detail: `仅 ${tools.join("、") || "单一扫描器"} 报出，未获交叉验证` };
  }
  return { label: "—", tone: "badge-muted", detail: "本次扫描未执行交叉验证" };
}
function scaConfidenceText(finding: Finding): string {
  const c = String(scaMeta(finding).confidence || "").toLowerCase();
  if (c === "high") return "高置信";
  if (c === "medium") return "中置信";
  if (c === "low") return "低置信";
  return "";
}
// ---- Q2：A1 去重聚合 ----
// A1 是规则模式命中，同一文件内同一规则常重复命中数十次（实测：路径穿越 20 条中
// 15 条同在 SystemUtils.java）。按「规则 + 文件」聚合成组，保留组内最高严重度者为代表。
const a1Grouped = ref(true);
const a1Expanded = ref<Set<string>>(new Set());
function toggleA1Group(key: string) {
  const next = new Set(a1Expanded.value);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  a1Expanded.value = next;
}
const currentStageFindings = computed(() => {
  const key = activeStageValue.value.key;
  return key === "a1" || key === "a2" ? findingsForStage(key) : [];
});
// 总览永久隐藏「非有效」发现（SCA 已修复/不受影响、A1/A2 误报·无证据），缓解数字墙。
function _isClearlyInvalid(finding: Finding): boolean {
  const v = verificationStateValue(finding);
  return v === "false_positive" || v === "no_evidence";
}
const overviewScaFindings = computed(() =>
  scaDisplayFindings.value.filter((f) => scaMeta(f).not_affected !== true));
const overviewStageFindings = computed(() =>
  currentStageFindings.value.filter((f) => !_isClearlyInvalid(f)));
// Q7 去密：Overview 的大表默认只渲染前 N 行 —— 一屏堆几百行是「数字墙」的主要来源。
// 需要时再展开；切换阶段自动收回，避免「展开过一次就永久全量渲染」。
const OVERVIEW_ROW_LIMIT = 20;
const overviewRowsExpanded = ref(false);
const overviewStageRows = computed(() =>
  overviewRowsExpanded.value ? overviewStageFindings.value : overviewStageFindings.value.slice(0, OVERVIEW_ROW_LIMIT));
const overviewScaRows = computed(() =>
  overviewRowsExpanded.value ? overviewScaFindings.value : overviewScaFindings.value.slice(0, OVERVIEW_ROW_LIMIT));
watch(() => activeStageValue.value?.key, () => {
  overviewRowsExpanded.value = false;
});
function severityRank(value?: string): number {
  const v = String(value || "").toUpperCase();
  if (v === "CRITICAL") return 4;
  if (v === "HIGH") return 3;
  if (v === "MEDIUM") return 2;
  if (v === "LOW") return 1;
  return 0;
}
interface A1GroupRow {
  key: string;
  rule: string;
  file: string;
  count: number;
  lines: number[];
  severity: string;
  representative: Finding;
  description: string;
}
const a1GroupRows = computed<A1GroupRow[]>(() => {
  if (activeStageValue.value.key !== "a1") return [];
  const groups = new Map<string, A1GroupRow>();
  for (const finding of overviewStageFindings.value) {
    const raw = (finding.raw || {}) as Record<string, any>;
    const rule = String(raw.rule_name || finding.finding_type || raw.type || "规则");
    const file = String(finding.file_path || raw.file || "");
    const key = `${rule}||${file}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.lines.push(Number(finding.line || 0));
      if (severityRank(finding.severity) > severityRank(existing.severity)) {
        existing.severity = String(finding.severity || "");
        existing.representative = finding;
      }
      continue;
    }
    groups.set(key, {
      key,
      rule,
      file,
      count: 1,
      lines: [Number(finding.line || 0)],
      severity: String(finding.severity || ""),
      representative: finding,
      description: String(raw.description || ""),
    });
  }
  return [...groups.values()]
    .map((group) => ({ ...group, lines: [...new Set(group.lines)].sort((a, b) => a - b) }))
    .sort((a, b) => b.count - a.count);
});
function truncateText(value: string, limit: number): string {
  const text = String(value || "").trim();
  if (!text) return "—";
  return text.length > limit ? `${text.slice(0, limit)} …` : text;
}
const scaCrossValidatedCount = computed(() => scaFindings.value.filter((f) => scaMeta(f).cross_validated === true).length);
const scaNotAffectedCount = computed(() => scaFindings.value.filter((f) => scaMeta(f).not_affected === true).length);
const scaUncheckedCount = computed(() => scaFindings.value.filter((f) => scaMeta(f).not_affected === undefined).length);

// ---- Q1：SCA 并集/交集（osv检测 / 双重检测）前端展示 ----
// 后端统一去重：同一组件漏洞在「双重检测」中只计一次（已按 CVE 别名合并，不会重复报）。
// 并集 = 全量（保召回），交集 = 被 ≥2 个不同扫描器共同报出的高置信（准）。用户自取信哪种数据。
const scaResult = computed<Record<string, any> | null>(() => {
  const summary = store.selectedTask?.summary as Record<string, any> | undefined;
  const sr = (summary?.stage_results as Record<string, any> | undefined) || {};
  const results = (summary?.results as Record<string, any> | undefined) || {};
  return (sr.sca as Record<string, any> | undefined)
      || (results.sca as Record<string, any> | undefined) || null;
});
const scaUnionCount = computed(() => {
  const v = Number(scaResult.value?.union_count);
  if (Number.isFinite(v) && v > 0) return v;
  return scaFindings.value.length;
});
const scaIntersectionCount = computed(() => {
  const v = Number(scaResult.value?.intersection_count);
  if (Number.isFinite(v) && v > 0) return v;
  return scaCrossValidatedCount.value;
});
const scaSingleToolCount = computed(() => {
  const v = Number(scaResult.value?.single_tool_count);
  if (Number.isFinite(v) && v > 0) return v;
  return Math.max(0, scaUnionCount.value - scaIntersectionCount.value);
});
// 视图切换：全量并集（osv检测） vs 仅双重检测（交集）
const scaView = ref<"union" | "double">("union");
const scaDisplayFindings = computed(() => {
  if (scaView.value === "double") {
    return scaFindings.value.filter((f) => scaMeta(f).cross_validated === true);
  }
  return scaFindings.value;
});
function scaDetectionLabel(finding: Finding): string {
  const dt = String(scaMeta(finding).detection_type || "");
  if (dt === "double") return "双重检测";
  if (dt === "osv-scanner") return "osv 检测";
  if (dt === "grype") return "grype 检测";
  if (dt === "trivy") return "trivy 检测";
  // 兜底：按 detected_by 推断
  const tools = (scaMeta(finding).detected_by || []).filter(Boolean);
  if (tools.length >= 2) return "双重检测";
  if (tools.length === 1) return String(tools[0]);
  return "未标注";
}
function scaDetectionTone(finding: Finding): string {
  const dt = String(scaMeta(finding).detection_type || "");
  if (dt === "double") return "badge-success";
  const tools = (scaMeta(finding).detected_by || []).filter(Boolean);
  if (tools.length >= 2) return "badge-success";
  return "badge-warning";
}

// ---- Q2/Item4：业务逻辑 / BOLA 作为 A1 一级 family findings，与注入类共用同一组流水线卡片 ----
// 视觉上连续：在 A1/A2 卡片内用「业务逻辑/越权」徽章标注，不另起独立面板。
const BUSINESS_LOGIC_FAMILIES = new Set(["business-logic", "bola", "idor", "privilege-escalation", "auth-session", "state-machine", "calculation-logic", "abuse-dos", "vertical-privilege", "authentication-bypass"]);
function isBusinessLogic(finding: Finding): boolean {
  const raw = (finding.raw || {}) as Record<string, any>;
  if (raw.a1_evidence?.business_logic === true) return true;
  const fam = String(raw.a1_evidence?.family || finding.finding_type || raw.type || "").toLowerCase();
  if (BUSINESS_LOGIC_FAMILIES.has(fam)) return true;
  const cat = String(raw.a1_evidence?.category || "").toLowerCase();
  if (BUSINESS_LOGIC_FAMILIES.has(cat)) return true;
  return false;
}
function businessLogicLabel(finding: Finding): string {
  const raw = (finding.raw || {}) as Record<string, any>;
  const cat = String(raw.a1_evidence?.category || finding.finding_type || raw.type || "").toLowerCase();
  return FAMILY_ZH[cat] || FAMILY_ZH[String(raw.a1_evidence?.family || "").toLowerCase()] || "业务逻辑";
}
const hasBusinessLogicFindings = computed(() => overviewStageFindings.value.some((f) => isBusinessLogic(f)));

// ---- 流量类型判定：前端镜像后端 derive_flow_type ----
// 优先用后端写回的 flow_type 字段（findings 已回填、AP/D1/D2/I2 新扫描带该字段）；
// 历史任务子结构无该字段时，按 family/type 在前端确定性重算，与后端同口径。
// 成员集合 = 后端 DIFFERENTIAL_PROOF_FAMILIES(9 类) + 别名表全量（每键已做 space→'-' 归一）。
const BUSINESS_LOGIC_MEMBERSHIP = new Set<string>([
  "bola", "idor", "vertical_privesc", "cross_module_privesc", "state_machine", "race",
  "calculation_logic", "auth_session", "abuse_dos",
  "race-condition", "concurrent", "并发超发", "并发超发竞态条件", "竞态条件", "竞态",
  "state-machine", "状态机", "状态机跳步", "workflow-bypass", "workflow", "statemachine",
  "b-o-l-a", "水平越权", "水平越权idor", "水平越权(idor)", "水平越权-(idor)",
  "越权-水平", "horizontal-privilege-escalation",
  "vertical", "vertical-privesc", "垂直越权", "越权-垂直", "privilege-escalation",
  "vertical-privilege-escalation", "privesc",
  "cross-module-privesc", "cross-module-privilege-escalation", "跨模块越权", "cross-module", "cross-business",
  "calculation", "金额篡改", "amount-tampering", "amount-manipulation", "quantity-tampering",
  "mass-assignment", "批量赋值", "property-injection",
  "auth-session", "auth", "认证", "jwt", "jwt-forgery", "jwt-token-forgery",
  "jwt-token-manipulation", "jwt安全漏洞", "authentication-bypass", "auth-bypass", "authorization-bypass",
  // 2026-09-17（待请示 §1.1 方案 A）：移除 "csrf"。csrf 是技术族，非业务差分族；
  // 后端 exploit_spec._BUSINESS_LOGIC_FAMILY_ALIASES 已同步删除 "csrf":"abuse_dos"，
  // derive_flow_type("csrf") 现返 "injection"。此镜像必须与后端保持一致。
  "abuse", "dos", "重放攻击", "replay-attack", "refund-abuse", "business-logic-abuse",
  "business-logic", "business-logic-bypass",
  "signature_bypass", "signature", "jwt_forgery", "jwt-forgery", "alg_none", "alg-none",
  "rsa_confusion", "sig_none", "signature-verification-bypass",
  // —— 2026-09-02 别名表缺口补全（与后端 exploit_spec.py 同步）——
  "业务逻辑", "退款滥用", "垂直越权-(privilege-escalation)",
  "business-logic-manipulation", "unauthorized-access", "concurrent-race-condition",
  "signature-bypass", "signature-forgery",
]);
// 第三轴（暴露/配置/弱加密类）：信息泄露 / 敏感信息泄露 / 配置安全 / 弱哈希 / 弱密钥 / 点击劫持。
// 既非注入型（无污点 sink 重放）、亦非业务差分（无双账户差分），仅做分类展示，不计入 18/17。
// 成员集合 = 后端 EXPOSURE_OR_CONFIG_FAMILIES(4 类) + 别名表全量（与 exploit_spec._EXPOSURE_FAMILY_ALIASES 同步）。
const EXPOSURE_MEMBERSHIP = new Set<string>([
  "information-disclosure", "info-disclosure", "信息泄露", "敏感信息泄露", "敏感数据泄露",
  "information disclosure", "sensitive-data-exposure", "data-exposure", "信息泄漏",
  "config-security", "配置安全", "配置不当", "安全配置", "security-misconfiguration", "misconfiguration",
  "weak-crypto", "弱哈希", "弱密钥问题", "弱加密", "弱密钥", "weak-hash", "weak-key", "weak-cipher", "弱密码",
  "clickjacking", "点击劫持",
]);
function deriveFlowTypeFrontend(fam?: string | null): "business_logic" | "injection" | "exposure" {
  const norm = String(fam || "").trim().toLowerCase().replace(/ /g, "-");
  if (!norm) return "injection"; // 空族宽松兜底，与后端 derive_flow_type('') 一致
  if (BUSINESS_LOGIC_MEMBERSHIP.has(norm)) return "business_logic";
  if (EXPOSURE_MEMBERSHIP.has(norm)) return "exposure";
  return "injection";
}
function flowTypeOf(item: any, kind?: "finding" | "ap" | "d1" | "d2" | "i2"): "business_logic" | "injection" | "exposure" {
  if (!item) return "injection";
  const direct = item.flow_type || (item.raw && item.raw.flow_type);
  if (direct === "business_logic" || direct === "injection" || direct === "exposure") return direct;
  let fam = "";
  if (kind === "finding") fam = item.raw?.display_family || item.raw?.family || item.raw?.type || item.raw?.category || item.finding_type || "";
  else if (kind === "ap") fam = item.family || "";
  else if (kind === "d1") fam = item.family || "";
  else if (kind === "d2") fam = item.type || item.family || "";
  else if (kind === "i2") fam = item.finding_type || item.type || "";
  else fam = item.family || item.type || item.finding_type || (item.raw && item.raw.family) || "";
  return deriveFlowTypeFrontend(fam);
}
function countsFor<T>(list: T[], kind?: "finding" | "ap" | "d1" | "d2" | "i2") {
  const c: { all: number; business_logic: number; injection: number; exposure: number } = { all: list.length, business_logic: 0, injection: 0, exposure: 0 };
  for (const it of list) c[flowTypeOf(it, kind)] += 1;
  return c;
}

function reviewMetric(key: string): number | string {
  // 多源兜底：API 返回的 reviewMetrics > summary.results.ai_review > summary.pipeline.ai_review.metrics
  const api = (reviewMetrics.value as Record<string, unknown>)?.[key];
  if (api !== undefined && api !== null && api !== "") return api as number | string;
  const fromResults = (store.selectedTask?.summary?.results as any)?.ai_review?.[key];
  if (fromResults !== undefined && fromResults !== null && fromResults !== "") return fromResults;
  const fromPipeline = (store.selectedTask?.summary?.pipeline as any)?.ai_review?.metrics?.[key];
  if (fromPipeline !== undefined && fromPipeline !== null && fromPipeline !== "") return fromPipeline;
  return 0;
}
function metricValue(key: string) {
  return String(reviewMetric(key));
}

function percentMetric(key: string) {
  const raw = Number(reviewMetric(key)) || 0;
  return `${Math.round(raw * 1000) / 10}%`;
}

async function runAiReview(finding: Finding) {
  await store.runAiReview(finding.id);
}

async function generateFix(finding: Finding) {
  await store.generateFixSuggestion(finding.id);
}

async function generatePatch(finding: Finding) {
  await store.generatePatchDraft(finding.id);
}

async function humanDecision(finding: Finding, decision: "true_positive" | "false_positive") {
  await store.submitHumanDecision(finding.id, {
    decision,
    reason_type: decision === "true_positive" ? "expert_accept_valid" : "expert_accept_false_positive",
    reason_detail: "Reviewed from SAST-AI task detail page",
    reviewer: "local",
  });
}

async function runEntryDiscovery() {
  const workspaceId = store.selectedTask?.workspace_id;
  const workspace = workspaceId ? store.selectedWorkspace || store.items.find((item) => item.id === workspaceId) : null;
  const projectPath = workspace?.target_path || String(store.selectedTask?.output_dir || "");
  if (!projectPath) return;
  await store.discoverEntries(projectPath);
}

function animateDashboard() {
  window.requestAnimationFrame(() => {
    if (!dashboardRoot.value) return;
    gsap.fromTo(
      dashboardRoot.value.querySelectorAll(".stat-card, .stage-card, .glow-card, .iast-finding-card, .evidence-step"),
      { y: 8, opacity: 0.72 },
      { y: 0, opacity: 1, duration: 0.35, stagger: 0.025, ease: "power2.out" },
    );
  });
}

function findingsForStage(stageName: "a1" | "a2" | "d2") {
  const findings = sortedFindings.value;
  if (stageName === "a1") return findings.filter((finding) => findingSources(finding).includes("A1"));
  if (stageName === "a2") return findings.filter((finding) => findingSources(finding).includes("A2"));
  return findings.filter((finding) => {
    const raw = finding.raw || {};
    return Boolean(
      raw.d2_status ||
        raw.d2_candidate_ready ||
        raw.poc_generated ||
        raw.poc_verified ||
        raw.verification_note ||
        raw.no_poc_reason ||
        raw.service_url ||
        raw.docker_attempted ||
        raw.docker_used ||
        raw.verification_decision,
    );
  });
}

function findingSources(finding: Finding) {
  const sources = finding.raw?.sources;
  if (Array.isArray(sources)) return sources.map((item) => String(item).toUpperCase());
  return [];
}

function pocChainSummary(finding: Finding): string[] {
  const raw = finding.raw as Record<string, any>;
  const chain = raw?.exploit_spec?.poc_chain || raw?.poc_chain;
  if (!Array.isArray(chain)) return [];
  return chain.map((node: any) => String(node?.node || node?.role || node?.signature || "")).filter(Boolean);
}

// §③ D2 未验证原因（2026-09-22）：报告层会为未获 D2 验证的 finding 写入显式原因状态
// （not_scheduled=未进 D2 执行队列；no_verification_record=已入队却无验证记录，属上游结果丢失）。
// 这两个状态是「未验证」，措辞必须避免任何可被读成「确认」的字样。
const D2_UNVERIFIED_STATUS_LABEL: Record<string, string> = {
  not_scheduled: "未排入 D2（未验证）",
  no_verification_record: "无验证记录（未验证）",
};

function stageFindingStatus(finding: Finding, stageName: "a1" | "a2" | "d2") {
  if (stageName === "a1" || stageName === "a2") return finding.severity;
  if (finding.raw?.verification_decision?.verification_status) {
    const status = String(finding.raw.verification_decision.verification_status);
    return D2_UNVERIFIED_STATUS_LABEL[status] || status;
  }
  if (finding.raw?.poc_verified) return "verified";
  if (finding.raw?.poc_generated) return "poc generated";
  if (finding.raw?.d2_candidate_ready) return "candidate ready";
  if (String(finding.raw?.exploitable || "") === "No") return "not exploitable";
  return "not executed";
}

function isProjectDeserializationChain(finding: Finding) {
  const raw = finding.raw || {};
  const canonicalKey = String(raw.canonical_group_key || "");
  const chainId = String(raw.chain_id || "");
  return canonicalKey === "deserialization:project_chain" || chainId === "deserialization:project_chain";
}

function displayFindingLabel(finding: Finding) {
  return String(finding.raw?.display_title || finding.raw?.chain_id || finding.raw?.display_family || finding.finding_type || "Unknown");
}

function displayFindingPath(finding: Finding) {
  if (isProjectDeserializationChain(finding)) {
    return "POST /debug/import -> QuoteService.setQuoteCache -> GET /api/quote/random -> CacheProcessor.process(userConfig)";
  }
  return String(finding.raw?.attack_chain_summary || finding.title || `${finding.file_path}:${finding.line}`);
}

function aiAnalysisSummary(finding: Finding): string {
  const raw = finding.raw || {};
  const ep = String(raw.entry_point || raw.http_entry_point || "").trim();
  const sink = String(raw.sink || raw.sink_method || "").trim();
  if (ep && sink) return `${ep} → ${sink}`;
  if (ep) return `${ep} → （危险函数未标注）`;
  if (sink) return `（入口未标注） → ${sink}`;
  return "A2 未产出入口/危险函数链路";
}

// ---- 双轴展示：severity（内在严重度）× 可达性/确认态（flow 是否证成）----
// sink 本身不等于危险：只有 source→sink 可达且中间无 barrier，才允许断言危险。
// A1 是规则模式命中（CodeQL/启发式），不走污点流四维度评判，单独展示「XX规则命中」。
const FAMILY_ZH: Record<string, string> = {
  "sql injection": "SQL注入", "sql-injection": "SQL注入",
  "command injection": "命令注入", "command-execution": "命令执行",
  "code injection": "代码注入", "expression injection": "表达式注入",
  "template injection": "模板注入", "path traversal": "路径穿越",
  "path-injection": "路径注入", "ldap injection": "LDAP注入",
  "xpath injection": "XPath注入", "header injection": "头注入",
  "log injection": "日志注入", "xss": "XSS", "cross-site scripting": "XSS",
  "ssrf": "SSRF", "server-side request forgery": "SSRF",
  "deserialization": "反序列化", "unsafe deserialization": "反序列化",
  "xxe": "XXE", "xml external entity": "XXE",
  "nosql injection": "NoSQL注入", "no-sql-injection": "NoSQL注入",
  "business-logic": "业务逻辑", "privilege-escalation": "权限提升",
  "authentication-bypass": "认证绕过", "resource-exhaustion": "资源耗尽",
  "idor": "IDOR", "bola": "越权", "auth-session": "会话认证",
  "state-machine": "状态机", "calculation-logic": "计算逻辑", "abuse-dos": "滥用DOS",
  "open-redirect": "开放重定向", "url-redirection": "开放重定向",
};

function isRuleHit(finding: Finding): boolean {
  const raw = finding.raw as Record<string, any> | undefined;
  if (raw?.detection_method === "rule") return true;
  // 兜底：findings.source 列存的是族名（如 ssrf），A1 来源在 raw.sources 列表里（['A1'] / ['A1','A2']）
  const sources = Array.isArray(raw?.sources) ? (raw?.sources as unknown[]) : [];
  return sources.some((s) => String(s).toUpperCase().startsWith("A1"));
}

function ruleHitLabel(finding: Finding): string {
  if (isBusinessLogic(finding)) return `${businessLogicLabel(finding)}假说`;
  const raw = finding.raw as Record<string, any> | undefined;
  if (raw?.rule_name) return `${raw.rule_name}规则命中`;
  const t = String(finding.finding_type || raw?.type || "");
  const zh = FAMILY_ZH[t.toLowerCase()];
  if (zh) return `${zh}规则命中`;
  return `${t || "规则"}规则命中`;
}

function taintFlow(finding: Finding): TaintFlowHypothesis | null {
  const raw = finding.raw as Record<string, any> | undefined;
  const flow = raw?.taint_flow_hypothesis as TaintFlowHypothesis | undefined;
  return flow && Object.keys(flow).length ? flow : null;
}

function flowBadge(finding: Finding): { label: string; tone: string; detail: string } {
  const raw = finding.raw as Record<string, any> | undefined;
  // A1 规则模式命中：不走污点流四维度评判
  if (isRuleHit(finding)) {
    return {
      label: ruleHitLabel(finding),
      tone: "flow-rule",
      detail: "A1 基于规则模式命中（CodeQL / 启发式），尚未做 source→sink 污点流证成",
    };
  }
  const refuted = ((raw?.verification_decision as any)?.proof_diff?.refuted || []) as string[];
  if (refuted.includes("gate_bypass_or_satisfaction_proven")) {
    return { label: "存在净化器（已反驳）", tone: "flow-refuted", detail: "运行时观测到净化/归一化，source→sink 被 barrier 截断" };
  }
  const flow = taintFlow(finding);
  if (!flow) {
    return { label: "未评估", tone: "flow-unknown", detail: "A2 未产出污点流假说" };
  }
  // §fix：静态未定位 sink 点时，绝不显示「完整流已证」——链路不完整，不可断言危险
  if (!flow.sink_present) {
    return { label: "未定位 sink 点（链路不完整）", tone: "flow-hypothesis", detail: "已证链路可达但静态未识别 sink 点，需运行时 IAST 观测佐证方可断言危险" };
  }
  if (flow.flow_complete || raw?.confirmed) {
    return { label: "完整流已证（危险可信）", tone: "flow-confirmed", detail: "source→sink 可达且无 barrier，可断言危险" };
  }
  if (flow.sink_present && !flow.source_present) {
    return { label: "仅识别 sink（假说）", tone: "flow-hypothesis", detail: "只发现危险函数调用点，未证出攻击者可控 source" };
  }
  if (flow.source_present && flow.sink_present && !flow.reachable) {
    return { label: "source→sink 不可达", tone: "flow-hypothesis", detail: "有 source 与 sink，但未证出可达路径" };
  }
  if (!flow.barrier_free) {
    return { label: "中间存在 barrier", tone: "flow-hypothesis", detail: "未证明 gate/barrier 被绕过或满足" };
  }
  return { label: "流未证成（未确认）", tone: "flow-hypothesis", detail: "污点流证明义务未闭合" };
}

function flowDims(finding: Finding): string {
  // A1 规则命中不展示污点流四维度（无意义）
  if (isRuleHit(finding)) return "";
  const flow = taintFlow(finding);
  if (!flow) return "";
  return [
    `source:${flow.source_present ? "有" : "无"}`,
    `sink:${flow.sink_present ? "有" : "无"}`,
    `可达:${flow.reachable ? "是" : "否"}`,
    `无 barrier:${flow.barrier_free ? "是" : "否"}`,
  ].join(" · ");
}

function severityDowngraded(finding: Finding): boolean {
  const raw = finding.raw as Record<string, any> | undefined;
  const claimed = String(raw?.severity_claimed || "").trim();
  return Boolean(claimed) && claimed.toUpperCase() !== String(finding.severity || "").toUpperCase();
}

function verificationStatusLabel(finding: Finding) {
  const status = String(finding.raw?.verification_decision?.verification_status || "");
  return D2_UNVERIFIED_STATUS_LABEL[status] || status;
}

// Q1 呈现层：验证状态独立列。A2 静态判定与 D2 动态判定各占一列，互不覆盖。
// 四态：confirmed=已验证利用 / detected_unverified=已检出未验证 / disproven=动态证伪 / static_pending=静态待确认。
// 关键点：detected_unverified 用琥珀色（badge-warning），绝不用红色——它代表「A2 判真漏洞、D2 没实证」，
// 是「已检出未验证」而非「已排除」，不能渲染成 ❌/No。
function verificationStateValue(finding: Finding): string {
  const v = (finding.raw as Record<string, unknown>)?.verification_state;
  return typeof v === "string" ? v : "";
}
function verificationStateLabel(finding: Finding): string {
  switch (verificationStateValue(finding)) {
    case "confirmed": return "已验证利用";
    case "detected_unverified": return "已检出未验证";
    case "disproven": return "动态证伪";
    case "static_pending": return "静态待确认";
    default: return "静态待确认";
  }
}
function verificationStateTone(finding: Finding): string {
  switch (verificationStateValue(finding)) {
    case "confirmed": return "success";
    case "detected_unverified": return "warning";
    case "disproven": return "muted";
    case "static_pending": return "muted";
    default: return "muted";
  }
}
function verificationStateHint(finding: Finding): string {
  switch (verificationStateValue(finding)) {
    case "confirmed": return "D2 动态验证确认可利用";
    case "detected_unverified": return "A2 静态判为真漏洞，但 D2 未给出动态实证：属「已检出未验证」，不是「已排除」";
    case "disproven": return "D2 动态证伪，非真实漏洞";
    case "static_pending": return "静态待确认";
    default: return "";
  }
}
// A2 静态判定独立列：展示 A2 在 SAST 阶段的静态结论，不随 D2 动态结果被改写。
function staticVerdictValue(finding: Finding): string {
  const v = (finding.raw as Record<string, unknown>)?.static_verdict;
  return typeof v === "string" ? v : "";
}
function staticVerdictShort(finding: Finding): string {
  const t = staticVerdictValue(finding);
  if (!t) return "—";
  if (t.includes("真漏洞")) return "A2 判真漏洞";
  if (t.includes("待确认") || t.includes("未确认")) return "A2 待确认";
  return t.length > 16 ? t.slice(0, 16) + "…" : t;
}
function staticVerdictTone(finding: Finding): string {
  const t = staticVerdictValue(finding);
  if (t.includes("真漏洞")) return "success";
  if (t.includes("待确认") || t.includes("未确认")) return "muted";
  return "info";
}

function verificationReason(finding: Finding) {
  return String(finding.raw?.verification_decision?.judge_reason || "");
}

function matchedOutcomesText(finding: Finding) {
  const items = finding.raw?.verification_decision?.matched_outcomes;
  return Array.isArray(items) ? items.join(", ") : "";
}

function requestsText(finding: Finding) {
  const items = finding.raw?.execution_evidence?.requests_made;
  return Array.isArray(items) ? items.join(" | ") : "";
}

function sideEffectsText(finding: Finding) {
  const items = finding.raw?.execution_evidence?.side_effects_observed;
  return Array.isArray(items) ? items.join(", ") : "";
}

function cleanupText(finding: Finding) {
  const items = finding.raw?.execution_evidence?.cleanup_performed;
  return Array.isArray(items) ? items.join(", ") : "";
}

async function loadPreferredReport() {
  const preferred =
    store.reports.find((item) => item.report_type === "FINAL_REPORT") ||
    store.reports.find((item) => item.report_type === "B2_MD") ||
    store.reports.find((item) => item.report_type === "B2_JSON") ||
    store.reports[0];
  if (!preferred) {
    store.selectReport(null);
    return;
  }
  await selectReport(preferred);
}

async function selectReport(report: ReportRecord) {
  reportLoading.value = true;
  try {
    store.selectReport(report);
    await store.fetchReportContent(report.id);
  } finally {
    reportLoading.value = false;
  }
}

function pct(value: unknown) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return `${(n * 100).toFixed(0)}%`;
}

function iastStateLabel(f: IastCorrelationFinding) {
  const s = f.iast?.state;
  if (s === "sink-reached") return "confirmed_runtime";
  if (s === "arrival-sanitized") return "arrival-sanitized";
  if (s === "no-arrival") return "no-arrival";
  return "no-observation";
}

function iastStateTone(f: IastCorrelationFinding) {
  const s = f.iast?.state;
  if (s === "sink-reached") return "success";
  if (s === "arrival-sanitized") return "warning";
  if (s === "no-arrival") return "danger";
  return "muted";
}

function entryParams(entry: Record<string, unknown>) {
  const params = entry.request_params as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(params) || !params.length) return [];
  return params.map((p) => {
    const name = String(p.param_name || "-");
    const loc = String(p.param_location || "");
    return loc ? `${name} (${loc})` : name;
  });
}

function iastRuntimeState(finding: Finding) {
  // §3.2/§3.3 摄取落库合一：按 hash 对齐 IAST 关联，返回该 finding 的运行时状态。
  const hash = String((finding.raw as Record<string, unknown>)?.vulnerability_hash_v2 || "");
  if (!hash) return null;
  const hit = iastFindings.value.find((f) => f.vulnerability_hash_v2 === hash);
  return hit?.iast?.state || null;
}

function iastRuntimeTone(state: string | null) {
  if (state === "sink-reached") return "success";
  if (state === "arrival-sanitized") return "warning";
  return "muted";
}

async function loadIastCorrelation() {
  if (!store.selectedTask) return;
  const taskId = store.selectedTask.id;
  const wsId = Number(store.selectedTask.workspace_id || 0);
  await Promise.all([
    iastStore.fetchCorrelation({ task_id: taskId, workspace_id: wsId || undefined }),
    iastStore.fetchAdjudication({ task_id: taskId, workspace_id: wsId || undefined }),
    iastStore.fetchTaskEventsSummary(taskId),
    iastStore.fetchTriggerSpecs({ task_id: taskId, workspace_id: wsId || undefined }),
  ]);
}

function evidenceStageLabel(stage: string) {
  return { SAST: "SAST 种子", DAST: "DAST 触发", IAST: "IAST 观测", D2: "D2 校验" }[stage] || stage;
}

function isTypedCanary(marker: string) {
  // §7.2 typed canary：数字 ID 后缀 / url 路径形态 / enum_ 前缀
  if (!marker) return false;
  const suffix = marker.replace(/^s4st41[0-9a-f]{16}/, "");
  return /^\d{8,}/.test(suffix) || suffix.startsWith("/") || suffix.startsWith("enum_");
}

function typedCanaryLabel(marker: string) {
  if (!isTypedCanary(marker)) return "";
  const suffix = marker.replace(/^s4st41[0-9a-f]{16}/, "");
  if (/^\d{8,}/.test(suffix)) return "typed·numeric_id";
  if (suffix.startsWith("/")) return "typed·url";
  if (suffix.startsWith("enum_")) return "typed·enum";
  return "typed";
}

function stabilityLabel(hash: string) {
  const d = iastStabilityMap.value.get(hash);
  if (!d) return "";
  return d.status === "likely-false-positive"
    ? `跨 ${d.stability_count} 次扫描稳定 → 疑似假阳性`
    : `已 ${d.stability_count} 次无观测`;
}

async function maybeRefreshArtifacts(taskId: number, event: TaskEvent) {
  const stage = String((event.payload.current_stage as string) || (event.payload.phase as string) || "");
  const now = Date.now();
  if (now - lastPartialRefresh < 1200) return;
  lastPartialRefresh = now;
  const stageResults = (event.payload.stage_results || {}) as Record<string, unknown>;
  const shouldRefreshTask = ["task_hitl_pending", "task_hitl_resolved", "task_suspended", "task_resumed"].includes(event.event_type) || Boolean(stage) || Boolean(event.payload.pipeline) || Object.keys(stageResults).length > 0;
  const shouldRefreshFindings = ["a2", "d2", "reporting", "completed", "failed"].includes(stage) || Boolean(event.payload.finding_count);
  const shouldRefreshReports = ["reporting", "completed", "failed"].includes(stage) || Boolean(event.payload.reports);
  const work: Promise<unknown>[] = [];
  if (shouldRefreshTask) work.push(store.fetchTask(taskId));
  if (shouldRefreshFindings) work.push(store.fetchTaskFindings(taskId));
  if (shouldRefreshReports) work.push(store.fetchTaskReports(taskId));
  if (event.event_type === "task_hitl_pending" || event.event_type === "task_hitl_resolved" || Boolean(event.payload.hitl)) {
    work.push(store.fetchTaskHitl(taskId));
  }
  if (["task_hitl_pending", "task_hitl_resolved", "task_suspended", "task_resumed"].includes(event.event_type) || Boolean(event.payload.hitl)) {
    work.push(store.fetchTaskHitlAudit(taskId));
  }
  if (work.length) {
    try {
      await Promise.all(work);
    } catch (error: any) {
      const status = Number(error?.response?.status || 0);
      if (status === 404) {
        store.selectedTask = null;
        socket?.close();
        await router.replace("/");
        return;
      }
      throw error;
    }
  }
  if (store.selectedReport) {
    const refreshed = store.reports.find((item) => item.id === store.selectedReport?.id) || store.reports[0];
    if (refreshed) {
      await selectReport(refreshed);
    }
  } else if (store.reports.length) {
    await loadPreferredReport();
  }
}

async function saveHitlSettings() {
  if (!store.selectedTask) return;
  await store.updateTaskHitl(store.selectedTask.id, {
    approval_mode: approvalModeDraft.value,
    tool_allowlist: allowlistDraft.value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
  });
}

async function resolvePendingAction(actionId: string, decision: "approved" | "rejected") {
  if (!store.selectedTask || !actionId) return;
  await store.resolveTaskHitlAction(store.selectedTask.id, actionId, decision);
  await refreshAudit();
}

async function allowlistAndApprove(actionId: string, toolId: string) {
  if (!store.selectedTask || !actionId || !toolId) return;
  const allowlist = allowlistDraft.value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!allowlist.includes(toolId)) {
    allowlist.push(toolId);
  }
  allowlistDraft.value = allowlist.join(", ");
  await store.updateTaskHitl(store.selectedTask.id, {
    approval_mode: approvalModeDraft.value,
    tool_allowlist: allowlist,
  });
  await store.resolveTaskHitlAction(store.selectedTask.id, actionId, "approved");
  await refreshAudit();
}

// ⑤-A 审计轨迹：拉取持久化的 guard 决策（跨重启可查）
async function refreshAudit() {
  if (!store.selectedTask) return;
  try {
    await store.fetchTaskHitlAudit(store.selectedTask.id);
  } catch {
    /* 审计拉取失败不阻断页面 */
  }
}

// ⑤-C 只读计划读取器（pending action 的 proposed_action 为弱类型，收敛在此）
function roPlan(action: Record<string, unknown>): Record<string, unknown> {
  const pa = action?.proposed_action;
  return pa && typeof pa === "object" ? (pa as Record<string, unknown>) : {};
}

// ① 不可逆判据（与后端 decide_hitl_gate / classify_destructive_operation 同源口径）
const IRREVERSIBLE_CATEGORIES = new Set<string>([
  "money_out",
  "data_destroy",
  "mass_assignment",
  "status_overwrite",
  "credential_mutation",
  "destructive_payload",
]);

// 动作类别取数：优先顶层 category（来自 act.category 单一真相源），缺失时回退 proposed_action.category
function actionCategory(action: Record<string, unknown>): string {
  const top = action?.category;
  if (typeof top === "string" && top) return top;
  const pa = action?.proposed_action;
  if (pa && typeof pa === "object") {
    const cat = (pa as Record<string, unknown>).category;
    if (typeof cat === "string" && cat) return cat;
  }
  return "uncategorized";
}

// 不可逆判定：优先显式 irreversible 布尔（未来口径），否则按类别集合
function isIrreversible(action: Record<string, unknown>): boolean {
  const pa = action?.proposed_action;
  const paObj = pa && typeof pa === "object" ? (pa as Record<string, unknown>) : {};
  if (action?.irreversible === true || paObj?.irreversible === true) return true;
  return IRREVERSIBLE_CATEGORIES.has(actionCategory(action));
}

// ① 按真实动作类别分组（类别取自 decide_hitl_gate 的 act.category 单一真相源）
const groupedPendingActions = computed(() => {
  const groups = new Map<string, { category: string; actions: Record<string, unknown>[]; hasIrreversible: boolean }>();
  for (const action of pendingActions.value) {
    const a = action as Record<string, unknown>;
    const cat = actionCategory(a);
    if (!groups.has(cat)) {
      groups.set(cat, { category: cat, actions: [], hasIrreversible: false });
    }
    const g = groups.get(cat)!;
    g.actions.push(a);
    if (isIrreversible(a)) g.hasIrreversible = true;
  }
  return Array.from(groups.values());
});

// ③ 全局不可逆计数（横幅展示）
const irreversibleCount = computed(
  () => pendingActions.value.filter((a) => isIrreversible(a as Record<string, unknown>)).length,
);

// ② 批量裁决已选中的不可逆计数与判定
const selectedIrreversibleCount = computed(() => {
  const set = new Set(selectedActionIds.value);
  return pendingActions.value.filter((a) => {
    const id = String((a as Record<string, unknown>).id || "");
    return set.has(id) && isIrreversible(a as Record<string, unknown>);
  }).length;
});
const batchHasIrreversible = computed(() => selectedIrreversibleCount.value > 0);

// ④ 审计 detail 美化（decide_hitl_gate 决策链 / 短接理由；detail 为对象时 JSON 美化）
function detailText(detail: unknown): string {
  if (!detail) return "";
  try {
    return typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
  } catch {
    return String(detail);
  }
}

// ⑤-B 批量裁决
function toggleSelectAll() {
  if (allSelected.value) {
    selectedActionIds.value = [];
  } else {
    selectedActionIds.value = pendingActions.value.map((a) => String((a as Record<string, unknown>).id || ""));
  }
}

async function batchResolve(decision: "approved" | "rejected") {
  if (!store.selectedTask || !selectedActionIds.value.length) return;
  const items = selectedActionIds.value
    .filter(Boolean)
    .map((id) => ({ action_id: id, decision }));
  await store.batchResolveTaskHitl(store.selectedTask.id, items);
  selectedActionIds.value = [];
  await refreshAudit();
}

// ⑤-D 挂起 / 恢复（恢复=重新提交=按已更新 allowlist 回填）
async function suspendSelectedTask() {
  if (!store.selectedTask) return;
  await store.suspendTask(store.selectedTask.id);
  await refreshAudit();
}

async function resumeSelectedTask() {
  if (!store.selectedTask) return;
  await store.resumeTask(store.selectedTask.id);
  await refreshAudit();
}

function startStaleWatcher(taskId: number) {
  if (staleTimer) window.clearInterval(staleTimer);
  lastLiveEventAt = Date.now();
  staleTimer = window.setInterval(async () => {
    if (Date.now() - lastLiveEventAt < 6000) return;
    if (!store.selectedTask) return;
    if (store.selectedTask.status === "completed" || store.selectedTask.status === "failed") return;
    try {
      await store.fetchTask(taskId);
    } catch (error: any) {
      const status = Number(error?.response?.status || 0);
      if (status === 404) {
        store.selectedTask = null;
        socket?.close();
        if (staleTimer) window.clearInterval(staleTimer);
        await router.replace("/");
        return;
      }
      throw error;
    }
  }, 3000);
}
</script>
