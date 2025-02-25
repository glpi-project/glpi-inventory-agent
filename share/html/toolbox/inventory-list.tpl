{ # This comment to keep a line feed at the beginning of this template inclusion }
  <form name='{$request}' method='post' action='{$url_path}/{$request}'>
    <input type='hidden' name='form' value='{$request}'/>
    <input type='hidden' id='display' name='display' value='{$display}'/>{
use Encode qw(encode);
use HTML::Entities;
use URI::Escape;

if (@jobs_order) {
  my $listnav = Text::Template::fill_in_file($template_path."/list-navigation.tpl", HASH => $hash);
  chomp($listnav) if defined($listnav);
  $OUT .= $listnav ? $listnav : "
    <div id='errors'><p>Error loading list-navigation.tpl template: $Text::Template::ERROR</p></div>";
  $OUT .= "
    <table class='inventory'>
      <thead>
        <tr>
          <th class='checkbox' title='"._("Revert selection")."'>
            <label class='checkbox'>
              <input class='checkbox' type='checkbox' onclick='toggle_all(this)'/>
              <span class='custom-checkbox all_cb'></span>
            </label>
          </th>";
  $other_order = $order eq 'ascend' ? 'descend' : 'ascend';
  foreach my $column (@columns) {
    my ($name, $text) = @{$column};
    my $order_req = $name eq $ordering_column ? $other_order : $order;
    $OUT .= "
          <th".($name eq $ordering_column ? " class='col-sort-$order'" : "").">
            <a class='noline' href='$url_path/$request?col=$name&order=$order_req'";
    $OUT .= "&start=$start" if $start;
    $OUT .= ">"._($text)."</a></th>";
  }
  $OUT .= "
        </tr>
      </thead>
      <tbody>";
  my $count = -$start;
  @visible = ();
  $listed = 0;
  foreach my $entry (@jobs_order) {
    next unless $count++>=0;
    $listed++;
    my $job         = $jobs{$entry};
    my $this        = encode('UTF-8', encode_entities($entry));
    my $name        = $job->{name} || $this;
    my $enabled     = $job->{enabled};
    my $type        = $job->{type} || "";
    $type = $job->{type} eq 'local' ? _"Local inventory" : _"Network scan"
        if $job->{type} && $job->{type} =~ /^local|netscan$/;
    my $config      = $job->{config} || "";
    my $scheduling  = $job->{scheduling} || [];
    my $lastrun     = $job->{last_run_date} ? localtime($job->{last_run_date}) : "";
    my $nextrun     = ($enabled ? localtime($job->{next_run_date}) : _"Disabled task") || "";
    my $description = $job->{description} || ($job->{config}->{ip} ? sprintf(_("%s network scan"), $job->{config}->{ip}) : "");
    $enabled        = $enabled ? "" : " disabled";
    my @runs        = sort { $tasks{$b}->{time} <=> $tasks{$a}->{time} } grep { defined($tasks{$_}->{name}) && $tasks{$_}->{name} eq $entry } keys(%tasks);
    my ($taskid)    = grep { defined($tasks{$_}->{name}) && $tasks{$_}->{name} eq $entry } keys(%tasks);
    $OUT .= "
        <tr class='$request'>
          <td class='checkbox'>
            <label class='checkbox'>
              <input class='checkbox' type='checkbox' name='checkbox/".encode_entities($entry)."'".
              ($form{"checkbox/".$entry} eq "on" ? " checked" : "")."/>
              <span class='custom-checkbox'></span>
            </label>
          </td>
          <td class='list' width='10%'>";
    $OUT .= "
          <div class='flex'>"
      if $taskid;
    $OUT .= "<a href='$url_path/$request?edit=".uri_escape($this)."'>$name</a>";
    $OUT .= "
            <div class='grow'></div>
            <i id='eye-$taskid' class='toggle-icon ti ti-eye".($show_task ? "-off" : "")."' onclick='toggle_show_task(\"$taskid\")' title='"._("Show task")."'></i>
            <i id='report-$taskid' class='toggle-icon ti ti-article".($show_report ? "-off" : "")."' onclick='toggle_show_task_report(\"$taskid\")' title='"._("Show task report")."'></i>
          "
      if $taskid;
    my @configuration;
    my $target = $config->{target};
    my @target_tooltip;
    if ($target && $targets{$target}) {
      @target_tooltip = ( $targets{$target}->[0], encode('UTF-8', encode_entities($targets{$target}->[1])));
    } elsif (!$default_local || $default_local eq '.') {
      $target = _("Agent folder");
      @target_tooltip = ( local => $target );
    } else {
      $target = _("Configured folder");
      @target_tooltip = ( local => "<tt>$default_local</tt>" );
    }
    push @configuration, _("Target").":&nbsp;
            <div class='with-tooltip'>$target
              <div class='tooltip bottom-tooltip'>
                <p>".join("</p><p>", @target_tooltip)."</p>
                <i></i>
              </div>
            </div>";
    if ($job->{type} eq 'netscan' && ref($config->{ip_range}) eq 'ARRAY') {
      push @configuration, _("IP range").": ".join(",", map { "
            <div class='with-tooltip'>
              <a href='$url_path/ip_range?edit=".uri_escape(encode("UTF-8", $_))."'>".encode('UTF-8', encode_entities($_))."
                <div class='tooltip bottom-tooltip'>
                  <p>"._("First ip").": ".$ip_range{$_}->{ip_start}."</p>
                  <p>"._("Last ip").": ".$ip_range{$_}->{ip_end}."</p>
                  <p>"._("Credentials").": ".join(",", map { encode('UTF-8', encode_entities($_)) } @{$ip_range{$_}->{credentials}//[]})."</p>
                  <i></i>
                </div>
              </a>
            </div>"
        } @{$config->{ip_range}});
      push @configuration, _("Threads").": ".$config->{threads}
        if $config->{threads};
      push @configuration, _("Timeout").sprintf(": %ds", $config->{timeout})
        if $config->{timeout};
    }
    push @configuration, _("Tag").": ".$config->{tag}
      if defined($config->{tag}) && length($config->{tag});
    my @scheduling;
    if (ref($scheduling) eq 'ARRAY') {
      foreach my $sched (sort @{$scheduling}) {
        if ($scheduling{$sched}->{type} eq 'delay') {
          my %units = qw( s second m minute h hour d day w week);
          my $delay = $scheduling{$sched}->{delay} || "24h";
          my ($number, $unit) = $delay =~ /^(\d+)([smhdw])?$/;
          $number = 24 unless $number;
          $unit = "h" unless $unit;
          $unit = $units{$unit};
          $unit .= "s" if $number > 1;
          $delay = $number." "._($unit);
          push @scheduling, "
            <div class='with-tooltip'>
              <a href='$url_path/scheduling?edit=".uri_escape(encode("UTF-8", $sched))."'>".encode('UTF-8', encode_entities($sched))."
                <div class='tooltip bottom-tooltip'>
                  <p>"._("Delay").": ".$delay."</p>".($scheduling{$sched}->{description} ? "
                  <p>"._("Description").": ".encode('UTF-8', $scheduling{$sched}->{description})."</p>" : "")."
                  <i></i>
                </div>
              </a>
            </div>";
        } elsif ($scheduling{$sched}->{type} eq 'timeslot') {
          my $weekday  = $scheduling{$sched}->{weekday}
            or next;
          my $start    = $scheduling{$sched}->{start}
            or next;
          my $duration = $scheduling{$sched}->{duration}
            or next;
          my ($hour, $minute) = $start =~ /^(\d{2}):(\d{2})$/
            or next;
          my ($dhour, $dminute) = $duration =~ /^(\d{2}):(\d{2})$/
            or next;
          push @scheduling, "
            <div class='with-tooltip'>
              <a href='$url_path/scheduling?edit=".uri_escape(encode("UTF-8", $sched))."'>".encode('UTF-8', encode_entities($sched))."
                <div class='tooltip bottom-tooltip'>
                  <p>"._("day").": ".($weekday eq '*' ? _("all") : _($weekday))."</p>
                  <p>"._("start").": ".$hour."h".$minute."</p>
                  <p>"._("duration").": ".$dhour."h".$dminute."</p>".($scheduling{$sched}->{description} ? "
                  <p>"._("Description").": ".encode('UTF-8', $scheduling{$sched}->{description})."</p>" : "")."
                  <i></i>
                </div>
              </a>
            </div>";
        }
      }
    }
    $OUT .= "</td>
          <td class='list' width='10%'>$type</td>
          <td class='list$enabled' width='10%'>".join(",", @scheduling)."</td>
          <td class='list$enabled' width='15%'".($taskid ? " id='$taskid-lastrun'" : "").">$lastrun</td>
          <td class='list$enabled' width='15%'".($taskid ? " id='$taskid-nextrun'" : "").">$nextrun</td>
          <td class='list'>
            <ul class='config'>
              ".join("", map { "
              <li class='config'>$_</li>" } @configuration)."
            </ul>
          </td>
          <td class='list'>$description</td>
        </tr>";
    if ($taskid) {
      my $task = $tasks{$taskid};
      my $ip_ranges = $tasks{$taskid}->{ip_ranges} || [];
      my $percent = $task->{percent} || 0;
      my $done    = $task->{done}    || 0;
      my $aborted = $task->{aborted} || 0;
      my $failed  = $task->{failed}  || 0;
      push @visible, $taskid;
      $OUT .= "
        <tr class='sub-row' id='run-$taskid'>
          <td class='checkbox'>&nbsp;</td>
          <td class='list' colspan='8'>
            <div class='task'>
              <div id='$taskid-progress' class='progress-col'>
                <div class='progress-bar'>
                  <div id='$taskid-scanned-bar' class='".($failed ? "failed" : $aborted ? "aborted" : ($percent == 100) ? "completed" : "scanning")."'>
                    <span id='$taskid-progress-bar-text' class='progressbar-text'>".(
                      $failed ? _("Failure") : $aborted ? _("Aborted") : ($percent == 100) ? _("Completed") : "")."</span>
                  </div>
                </div>
              </div>
            </div>";
      $OUT .= "
            <div id='$taskid-counters' class='task-details'>
              <div class='progress-col'>
                <div class='counters-row'>
                  <div class='counter-cell'>
                    <label>";
      if ($task->{islocal}) {
        $OUT .= _("Local inventory")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-inventory-count'>".($task->{inventory_count} || 0)."</span>
                  </div>
                </div>";
      } else {
        $OUT .= _("Created inventories")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-inventory-count' title='"._("Should match devices with SNMP support count")."'>
                      ".($task->{inventory_count} || 0).($task->{inventory_count} && $task->{snmp_support} ? "/".$task->{snmp_support} : "")."
                    </span>
                  </div>
                </div>
                <div class='counter-cell'>
                  <label>"._("Scanned IPs")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-scanned' title='"._("Scanned IPs for this IP range")."'>
                      ".($task->{count} || 0).($task->{count} && $task->{count} < $task->{maxcount} ? "/".$task->{maxcount} : "")."
                    </span>
                  </div>
                </div>
                <div class='counter-cell'>
                  <label>"._("Devices with SNMP support")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-snmp' title='"._("IPs for which we found a device supporting SNMP with provided credentials")."'>
                      ".($task->{snmp_support} || 0).($task->{snmp_support} && $task->{count} ? "/".$task->{count} : "")."
                    </span>
                  </div>
                </div>
                <div class='counter-cell'>
                  <label>"._("IPs without SNMP response")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-others' title='"._("These IPs are responding to ping or are found in ARP table")."\n".
                      _("But we didn't find any device supporting SNMP with provided credentials")."'>
                      ".($task->{others_support} || 0).($task->{others_support} && $task->{count} ? "/".$task->{count} : "")."
                    </span>
                  </div>
                </div>
                <div class='counter-cell'>
                  <label>"._("IPs without PING response")."</label>
                  <div class='counters-row'>
                    <span class='counter' id='$taskid-unknown' title='"._("IPs not responding to ping and not seen in ARP table")."'>
                      ".($task->{unknown} || 0).($task->{unknown} && $task->{count} ? "/".$task->{count} : "")."
                    </span>
                  </div>
                </div>";
      }
      my $freeze_status = " disabled";
      unless ($done || $percent == 100) {
        $freeze_status = " onclick='toggle_freeze_log(\"$taskid\")'";
        $freeze_status .= " checked" if $form{"freeze-log/$taskid"} && $form{"freeze-log/$taskid"} eq 'on';
      }
      my $verbosity = $form{"verbosity/$taskid"} // "debug";
      $OUT .= "
            </div>
            <div class='output-header'>
              <label class='switch'>
                <input id='show-log-$taskid' name='show-log/$taskid' class='switch' type='checkbox' onclick='show_log(\"$taskid\")'".($form{"show-log/$taskid"} && $form{"show-log/$taskid"} eq "on" ? " checked" : "")."/>
                <span class='slider'></span>
              </label>
              <label for='show-log-$taskid' class='text'>".sprintf( _("Show &laquo;&nbsp;%s&nbsp;&raquo; task log"), $this)."</label>
              <div class='abort-button'>
                <button class='inline secondary' id='$taskid-abort-button' type='button' name='abort/$taskid' alt='"._("Abort")."' onclick='abort_task(\"$taskid\")' style='display: ".($done || $percent == 100 || $aborted ? "none" : "inline")."'><i class='secondary ti ti-player-stop-filled'></i>"._("Abort")."</button>
              </div>
              <div class='log-freezer' id='$taskid-freeze-log' >
                <label class='switch' id='$taskid-freeze-log-option' style='display: ".($done || $percent == 100 || $aborted || !$form{"show-log/$taskid"} && !$form{"show-log/$taskid"} ne "on"? "none" : "inline")."'>
                  <input id='freeze-log-$taskid' name='freeze-log/$taskid' class='freezer-switch' type='checkbox'$freeze_status/>
                  <span class='slider'></span>
                </label>
                <label for='freeze-log-$taskid' class='text text-fix' id='$taskid-freeze-log-label' style='display: ".($done || $percent == 100 || $aborted || !$form{"show-log/$taskid"} && !$form{"show-log/$taskid"} ne "on"? "none" : "inline")."'>"._("Freeze log output")."</label>
              </div>
              <div class='verbosity-option' id='$taskid-verbosity-option'>
                "._("Verbosity").":
                <select id='$taskid-verbosity' name='verbosity/$taskid' class='verbosity-options' onchange='verbosity_change(\"$taskid\");'>";
      foreach my $opt (qw(info debug debug2)) {
        $OUT .= "
                  <option".($verbosity && $verbosity eq $opt ? " selected" : "").">$opt</option>";
      }
      $OUT .= "
                </select>
              </div>
            </div>
            <textarea id='$taskid-output' class='output' wrap='off' readonly style='display: none'></textarea>
          </td>
        </tr>";
    }
    last if $display && $count >= $display;
  }
  $OUT .= "
      </tbody>";
  if ($listed >= 50) {
    $OUT .= "
      <tbody>
        <tr>
          <th class='checkbox' title='"._("Revert selection")."'>
            <label class='checkbox'>
              <input class='checkbox' type='checkbox' onclick='toggle_all(this)'/>
              <span class='custom-checkbox all_cb'></span>
            </label>
          </th>";
    foreach my $column (@columns) {
      my ($name, $text) = @{$column};
      my $other_order = $order eq 'ascend' ? 'descend' : 'ascend';
      my $order_req = $name eq $ordering_column ? $other_order : $order;
      $OUT .= "
          <th".($name eq $ordering_column ? " class='col-sort-$order'" : "").">
            <a class='noline' href='$url_path/$request?col=$name&order=$order_req'";
      $OUT .= "&start=$start" if $start;
      $OUT .= ">"._($text)."</a></th>";
    }
    $OUT .= "
        </tr>
      </tbody>";
  }
  $OUT .= "
    </table>
    <div class='select-row'>
      <i class='ti ti-corner-left-up arrow-left'></i>
      <button class='secondary' type='submit' name='submit/run-now' alt='"._("Run task")."'><i class='secondary ti ti-player-play-filled'></i>"._("Run task")."</button>
      <div class='separation'></div>
      <button class='secondary' type='submit' name='submit/enable' alt='"._("Enable")."'><i class='secondary ti ti-settings-automation'></i>"._("Enable")."</button>
      <button class='secondary' type='submit' name='submit/disable' alt='"._("Disable")."'><i class='secondary ti ti-settings-off'></i>"._("Disable")."</button>
      <div class='separation'></div>
      <button class='secondary' type='submit' name='submit/delete' alt='"._("Delete")."'><i class='secondary ti ti-trash-filled'></i>"._("Delete")."</button>
    </div>";
  $OUT .= $listnav if $listed >= 50 && $listnav;
} else {
  # Handle empty list case
  $OUT .= "
    <div id='empty-list'>
      <p>"._("No inventory task defined")."</p>
    </div>";
}}
    <hr/>
    <button class='big-button' type='submit' name='submit/add' alt='{_"Add new inventory task"}'><i class='primary ti ti-plus'></i>{_"Add new inventory task"}</button>
  </form>
  <script>
  var outputids = [{ join(", ", map { "'$_'" } @visible) }];
  var output_index = \{{ join(", ", map { "'$_': 0" } @visible) }\};
  var timeouts = new Map([{ join(", ", map { "['$_',  0]" } @visible) }]);
  var freezed_log = \{{ join(", ", map { "'$_': false" } @visible) }\};
  var whats = \{{ join(", ", map { "'$_': 'full'" } @visible) }\};
  var ajax_queue = [];
  var ajax_trigger;
  var xhttp = window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject('Microsoft.XMLHTTP');
  function toggle_all(from) \{
    var all_cb = document.querySelectorAll('input[type="checkbox"]');
    for ( var i = 0; i < all_cb.length; i++ )
      if (all_cb[i].className === 'checkbox' && all_cb[i] != from)
        all_cb[i].checked = !all_cb[i].checked;
  \}
  function toggle_show_task(taskid) \{
    var eye = document.getElementById('eye-'+taskid);
    if (!eye.className.endsWith('-off')) \{
      eye.className = 'toggle-icon ti ti-eye-off';
      document.getElementById(taskid+'-progress').style.display = "block";
      sessionStorage.setItem('eye-'+taskid, true);
      document.getElementById('run-'+taskid).style.display = "table-row";
    \} else \{
      eye.className = 'toggle-icon ti ti-eye';
      document.getElementById(taskid+'-progress').style.display = "none";
      sessionStorage.removeItem('eye-'+taskid);
      document.getElementById('run-'+taskid).style.display = sessionStorage.getItem('report-'+taskid) ? "table-row" : "none";
    \}
  \}
  function toggle_show_task_report(taskid) \{
    var report = document.getElementById('report-'+taskid);
    if (!report.className.endsWith('-off')) \{
      report.className = 'toggle-icon ti ti-article-off';
      document.getElementById(taskid+'-counters').style.display = "flex";
      sessionStorage.setItem('report-'+taskid, true);
      document.getElementById('run-'+taskid).style.display = "table-row";
    \} else \{
      report.className = 'toggle-icon ti ti-article';
      document.getElementById(taskid+'-counters').style.display = "none";
      sessionStorage.removeItem('report-'+taskid);
      document.getElementById('run-'+taskid).style.display = sessionStorage.getItem('eye-'+taskid) ? "table-row" : "none";
    \}
  \}
  function set_status(taskid) \{
    var eye = 'eye-'+taskid;
    var report = 'report-'+taskid;
    var seen = sessionStorage.getItem('seen-'+taskid);
    if (!seen) \{ // Manage to always show progress bar first time we see a task
      sessionStorage.setItem('seen-'+taskid, true);
      sessionStorage.setItem(eye, true);
    \}
    var show_task = sessionStorage.getItem(eye);
    var show_report = sessionStorage.getItem(report);
    document.getElementById(eye).className = 'toggle-icon ti ti-eye'+(show_task ? "-off" : "");
    document.getElementById(taskid+'-progress').style.display = show_task ? "block" : "none";
    document.getElementById(report).className = 'toggle-icon ti ti-article'+(show_report ? "-off" : "");
    document.getElementById(taskid+'-counters').style.display = show_report ? "flex" : "none";
    document.getElementById('run-'+taskid).style.display = show_task || show_report ? "table-row" : "none";
  \}
  for ( var i = 0; i < outputids.length; i++ ) \{
    set_status(outputids[i]);
  \}
  function show_log(task) \{
    var output, checked, completed, aborted;
    checked = document.getElementById('show-log-'+task).checked;
    output = document.getElementById(task+'-output');
    completed = document.getElementById(task+'-scanned-bar').className === "completed";
    aborted = document.getElementById(task+'-scanned-bar').className === "aborted";
    failed = document.getElementById(task+'-scanned-bar').className === "failed";
    if (completed || aborted || failed) \{
      document.getElementById(task+'-abort-button').style.display = 'none';
      document.getElementById(task+'-freeze-log-option').style.display = 'none';
      document.getElementById(task+'-freeze-log-label').style.display = 'none';
    \} else \{
      document.getElementById(task+'-abort-button').style.display = 'inline';
      document.getElementById(task+'-freeze-log-option').style.display = checked ? 'inline' : 'none';
      document.getElementById(task+'-freeze-log-label').style.display = checked ? 'inline' : 'none';
    \}
    document.getElementById(task+'-verbosity-option').style.display = checked ? 'inline' : 'none';
    output.style.display = checked ? 'block' : 'none';
    if (checked && output.innerHTML === '') ajax_load('full', task);
  \}
  function toggle_freeze_log(task) \{
    var checked = document.getElementById('freeze-log-'+task).checked;
    freezed_log[task] = checked;
    if (!checked) ajax_load('full', task);
  \}
  xhttp.onreadystatechange = function() \{
    if (this.readyState === 4 && this.status === 200) \{
      var index, running, inventory_count, percent, task, output, aborted, last_run_date, checked;
      var enabled = false;
      task = this.getResponseHeader('X-Inventory-Task');
      output = document.getElementById(task+'-output');
      index = this.getResponseHeader('X-Inventory-Index');
      checked = document.getElementById('show-log-'+task).checked;
      last_run_date = this.getResponseHeader('X-Inventory-LastRunDate');
      if (!freezed_log[task]) \{
        if (this.getResponseHeader('X-Inventory-Output') === 'full' || (output_index[task] > 0 && index < output_index[task])) \{
          output.innerHTML = this.responseText;
          output.scrollTop = 0;
        \} else \{
          output.innerHTML += this.responseText;
          if (index && output_index[task] != index ) output.scrollTop = output.scrollHeight;
        \}
        if (index >= 0) output_index[task] = index;
      \}
      running = this.getResponseHeader('X-Inventory-Status') === 'running' ? true : false;
      aborted = this.getResponseHeader('X-Inventory-Status') === 'aborted' ? true : false;
      failed  = this.getResponseHeader('X-Inventory-Status') === 'failed'  ? true : false;
      inventory_count = this.getResponseHeader('X-Inventory-Count');
      if (!this.getResponseHeader('X-Inventory-IsLocal')) \{
        var scanned, maxcount, permax, percount, snmp, others, unknown;
        scanned = this.getResponseHeader('X-Inventory-Scanned');
        maxcount = this.getResponseHeader('X-Inventory-MaxCount');
        permax = maxcount && Number(scanned)<Number(maxcount)? "/"+maxcount : "";
        document.getElementById(task+'-scanned').innerHTML = scanned ? scanned+permax : 0;
        percount = scanned ? "/"+scanned : "";
        others = this.getResponseHeader('X-Inventory-With-Others');
        snmp = this.getResponseHeader('X-Inventory-With-SNMP');
        document.getElementById(task+'-others').innerHTML = others ? others+percount : 0;
        document.getElementById(task+'-snmp').innerHTML = snmp ? snmp+percount : 0;
        unknown = this.getResponseHeader('X-Inventory-Unknown');
        document.getElementById(task+'-unknown').innerHTML = unknown ? unknown+percount : 0;
        inventory_count = inventory_count+(Number(snmp)?"/"+snmp:"")
      \}
      document.getElementById(task+'-inventory-count').innerHTML = inventory_count ? inventory_count : 0;
      percent = this.getResponseHeader('X-Inventory-Percent');
      document.getElementById(task+'-scanned-bar').style.width = percent+"%";
      var show_task = sessionStorage.getItem('eye-'+task);
      if (percent === '100') \{
        if (!show_task) document.getElementById('eye-'+task).className = 'toggle-icon ti ti-eye'
        enabled = true;
        if (freezed_log[task]) \{
          whats[task] = 'full';
          freezed_log[task] = false;
        \} else \{
          whats[task] = 'status';
        \}
        document.getElementById(task+'-freeze-log-option').style.display = 'none';
        document.getElementById(task+'-freeze-log-label').style.display = 'none';
        document.getElementById(task+'-abort-button').style.display = 'none';
      \} else \{
        if (!show_task) document.getElementById('eye-'+task).className = 'toggle-icon ti ti-eye-exclamation'
        document.getElementById(task+'-freeze-log-option').style.display = checked ? 'inline' : 'none';
        document.getElementById(task+'-freeze-log-label').style.display = checked ? 'inline' : 'none';
        document.getElementById(task+'-abort-button').style.display = 'inline';
      \}
      if (aborted) \{
        document.getElementById(task+'-progress-bar-text').innerHTML = '{_"Aborted"}';
        document.getElementById(task+'-scanned-bar').className = "aborted";
        document.getElementById(task+'-scanned-bar').style.width = "100%";
      \} else if (failed) \{
        document.getElementById(task+'-progress-bar-text').innerHTML = '{_"Failure"}';
        document.getElementById(task+'-scanned-bar').className = "failed";
      \} else \{
        document.getElementById(task+'-scanned-bar').className = percent === '100' ? "completed" : "scanning";
        document.getElementById(task+'-progress-bar-text').innerHTML = percent === '100' ? '{_"Completed"}' : '';
      \}
      if (running || (!aborted && (!percent || percent != '100'))) \{
        enabled = true;
        if (this.responseText != '...') whats[task] = 'more';
      \}
      if (last_run_date) \{
        var next_run_date = this.getResponseHeader('X-Inventory-NextRunDate');
        var next_run_time = Number(this.getResponseHeader('X-Inventory-NextRunTime'));
        document.getElementById(task+'-lastrun').innerHTML = last_run_date;
        if (next_run_date) \{
          enabled = true;
          document.getElementById(task+'-nextrun').innerHTML = next_run_date;
          timeouts[task] = next_run_time * 1000;
        \} else \{
          enabled = false;
        \}
      \}
      if (enabled) outputids.push(task);
      if (ajax_queue.length) \{
        ajax_trigger = setTimeout(ajax_request, 100);
      \} else if (outputids.length) \{
        ajax_trigger = setTimeout(ajax_load, 100);
      \}
    \}
  \}
  function ajax_request() \{
    var url;
    if (ajax_queue.length) \{
      if (xhttp.readyState == 0 || xhttp.readyState == 4) \{
        url = ajax_queue.shift();
        xhttp.open('GET', url, true);
        xhttp.send();
      \} else \{
        ajax_trigger = setTimeout(ajax_request, 100);
      \}
    \}
  \}
  function ajax_load(what, task) \{
    var url, verbosity;
    var next_ajax_load = 100;
    if (!task) task = outputids.shift();
    if (task) \{
      if (!what) what = whats[task];
      url = '{$url_path}/{$request}/ajax?id='+task+'&what='+what;
      if (what === 'status') \{
        var timeout = timeouts[task];
        if (timeout && timeout > Date.now()) \{
          next_ajax_load = 1000;
          if (outputids.length)
            for ( var i = 0; i < outputids.length; i++ )
              if (!timeouts.has(outputids[i]) || timeouts[outputids[i]]-1000 < Date.now()) \{
                next_ajax_load = 100;
                break;
              \}
          outputids.push(task);
        \} else \{
          ajax_queue.push(url);
        \}
      \} else \{
        verbosity = document.getElementById(task+'-verbosity').value;
        if (verbosity) url += '&'+verbosity
        if (output_index[task] && what != 'full') url += '&index=' + output_index[task];
        ajax_queue.push(url);
      \}
      if (ajax_queue.length) \{
        ajax_trigger = setTimeout(ajax_request, 10);
      \} else \{
        ajax_trigger = setTimeout(ajax_load, next_ajax_load);
      \}
    \}
  \}
  function verbosity_change(task) \{
    if (ajax_trigger) clearTimeout(ajax_trigger);
    ajax_load('full', task);
  \}
  function abort_task(task) \{
    if (ajax_trigger) clearTimeout(ajax_trigger);
    ajax_load('abort', task);
  \}
  function htmldecode(str) \{
    var txt = document.createElement('textarea');
    txt.innerHTML = str;
    return txt.value;
  \}
  function check_all_expandable() \{
    var all_cb = document.querySelectorAll('input[type="checkbox"]');
    for ( var cb = all_cb[0], i = 0; i < all_cb.length; ++i, cb = all_cb[i] )
      if (cb.className === 'switch' && cb.checked) show_log(cb.id.slice(9));
  \}
  check_all_expandable();
  ajax_load();
  </script>
