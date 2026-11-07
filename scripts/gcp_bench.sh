#!/usr/bin/env bash
# Real-machine benchmarks on Google Cloud: three servers on three VMs.
#
#   scripts/gcp_bench.sh quota PROFILE     show the CPU quotas that limit `up`
#   scripts/gcp_bench.sh up PROFILE        create the 3 VMs (PROFILE: lan | wan)
#   scripts/gcp_bench.sh deploy PROFILE    copy this commit to each VM and build it there
#   scripts/gcp_bench.sh net PROFILE       measure round-trip times and bandwidth between the VMs
#   scripts/gcp_bench.sh run PROFILE N STAGE MODE [REPS]
#                                          REPS auctions (default 3), each checked against the reference
#                                          STAGE: 1 | 2   MODE: semi | malicious
#   scripts/gcp_bench.sh grid PROFILE      the full table for PROFILE (see GRID below)
#   scripts/gcp_bench.sh summary           medians of everything in results/gcp/
#   scripts/gcp_bench.sh down PROFILE      delete the 3 VMs  <-- always run this when done
#   scripts/gcp_bench.sh status            list darkmpc VMs that exist (and so are billing)
#
# LAN: all three VMs in one zone. WAN: one VM in each of three regions.
# Servers talk over the VPC's internal addresses, through the same mutually
# authenticated TLS as everywhere else, with no simulated delay: whatever
# the network does is what gets measured.
#
# Orders are dealt on this machine and copied to the VMs; that stands in for
# the traders. Every server receives every file in the deal directory (fine
# for a benchmark; in deployment a server gets only its own key and shares).
#
# Requirements: gcloud authenticated (gcloud auth login) with a default
# project set (gcloud config set project ...), and the project's default VPC
# network. Nothing here runs unless you invoke it. Bash 3.2 compatible.
set -euo pipefail
cd "$(dirname "$0")/.."

# n2-standard-2 (2 vCPUs each, 6 in total) fits free-trial quotas, which
# cap some machine families at 8 vCPUs per region and cannot be raised.
MACHINE=${MACHINE:-n2-standard-2}
IMAGE_FAMILY=${IMAGE_FAMILY:-debian-12}
IMAGE_PROJECT=${IMAGE_PROJECT:-debian-cloud}
LAN_ZONE=${LAN_ZONE:-us-west1-b}
WAN_ZONES=${WAN_ZONES:-"us-west1-b us-central1-a us-east4-a"}
PORT=7000
RESULTS=results/gcp
GRID_SIZES=${GRID_SIZES:-"100 1000 10000 100000"}
GRID_MAL_SIZES=${GRID_MAL_SIZES:-"100 1000 10000"}

die() { echo "error: $*" >&2; exit 1; }

zone_of() { # PROFILE INDEX
  if [ "$1" = lan ]; then echo "$LAN_ZONE"; else echo $WAN_ZONES | awk -v k=$(( $2 + 1 )) '{print $k}'; fi
}
name_of() { echo "darkmpc-$1-$2"; }
check_profile() { case "${1:-}" in lan|wan) ;; *) die "PROFILE must be lan or wan" ;; esac; }

ssh_vm() { # PROFILE INDEX COMMAND
  gcloud compute ssh "$(name_of "$1" "$2")" --zone "$(zone_of "$1" "$2")" --quiet --command "$3"
}
scp_dir_to() { # PROFILE INDEX LOCALDIR REMOTEDIR (REMOTEDIR must not exist)
  gcloud compute scp --recurse --zone "$(zone_of "$1" "$2")" --quiet "$3" "$(name_of "$1" "$2"):$4"
}
scp_file_to() { # PROFILE INDEX LOCALFILE REMOTEPATH
  gcloud compute scp --zone "$(zone_of "$1" "$2")" --quiet "$3" "$(name_of "$1" "$2"):$4"
}
scp_from() { # PROFILE INDEX REMOTEPATH LOCALDIR
  gcloud compute scp --zone "$(zone_of "$1" "$2")" --quiet "$(name_of "$1" "$2"):$3" "$4"
}

# Internal IPs, looked up once per profile and cached (only when all three exist).
IPS=()
load_ips() { # PROFILE
  local cache="$RESULTS/ips-$1" i ip
  mkdir -p "$RESULTS"
  if [ ! -f "$cache" ] || [ "$(wc -l < "$cache")" -ne 3 ]; then
    rm -f "$cache"
    local got=""
    for i in 0 1 2; do
      ip=$(gcloud compute instances describe "$(name_of "$1" $i)" --zone "$(zone_of "$1" $i)" \
        --format='get(networkInterfaces[0].networkIP)' 2>/dev/null) \
        || die "VM $(name_of "$1" $i) does not exist; run: scripts/gcp_bench.sh up $1"
      got="$got$ip"$'\n'
    done
    printf '%s' "$got" > "$cache"
  fi
  IPS=($(cat "$cache"))
  [ ${#IPS[@]} -eq 3 ] || { rm -f "$cache"; die "could not read the VMs' internal addresses"; }
}

machine_of() { # PROFILE: the machine type recorded by `up`, for labelling results
  cat "$RESULTS/machine-$1" 2>/dev/null || echo "$MACHINE"
}

# Run up to three background jobs and fail if any of them failed.
PIDS=()
wait_all() { # MESSAGE
  local pid failed=0
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" || failed=1; done
  PIDS=()
  [ $failed -eq 0 ] || die "$1"
}

cmd_quota() {
  check_profile "$1"
  local regions="" i r
  for i in 0 1 2; do
    r=$(zone_of "$1" $i); r=${r%-*}
    case " $regions " in *" $r "*) ;; *) regions="$regions $r" ;; esac
  done
  for r in $regions; do
    echo "== $r (limit, in use)"
    gcloud compute regions describe "$r" --flatten="quotas[]" \
      --format="csv[no-heading](quotas.metric,quotas.limit,quotas.usage)" | grep -E '^(CPUS|N2_CPUS|C3_CPUS|C4_CPUS|E2_CPUS),' || true
  done
  echo "== all regions"
  gcloud compute project-info describe --flatten="quotas[]" \
    --format="csv[no-heading](quotas.metric,quotas.limit,quotas.usage)" | grep -E '^CPUS_ALL_REGIONS,' || true
  echo "lan puts 3 x $MACHINE in one region; wan puts 1 in each of 3 regions. The VMs need that many vCPUs"
  echo "free under both CPUS and the family's own quota (N2_CPUS for n2-*, C3_CPUS for c3-*), and under CPUS_ALL_REGIONS."
}

cmd_up() {
  check_profile "$1"
  local i z
  gcloud config get-value project >/dev/null 2>&1 || die "no gcloud project set"
  gcloud compute networks describe default >/dev/null 2>&1 || die "this project has no 'default' VPC network"
  for i in 0 1 2; do
    z=$(zone_of "$1" $i)
    gcloud compute machine-types describe "$MACHINE" --zone "$z" >/dev/null 2>&1 \
      || die "$MACHINE is not offered in $z (set MACHINE, LAN_ZONE or WAN_ZONES)"
  done
  rm -f "$RESULTS/ips-$1"
  for i in 0 1 2; do
    gcloud compute instances create "$(name_of "$1" $i)" --zone "$(zone_of "$1" $i)" \
      --machine-type "$MACHINE" --image-family "$IMAGE_FAMILY" --image-project "$IMAGE_PROJECT" \
      --boot-disk-size 30GB --labels darkmpc=bench --quiet &
    PIDS+=($!)
  done
  local pid failed=0
  for pid in "${PIDS[@]}"; do wait "$pid" || failed=1; done
  PIDS=()
  if [ $failed -ne 0 ]; then
    echo "creating a VM failed; deleting the ones that were created so nothing is left billing" >&2
    cmd_down "$1"
    die "up failed (see the gcloud error above: QUOTA errors -> 'scripts/gcp_bench.sh quota $1'; ZONE_RESOURCE_POOL_EXHAUSTED -> pick another zone via LAN_ZONE or WAN_ZONES)"
  fi
  mkdir -p "$RESULTS"
  echo "$MACHINE" > "$RESULTS/machine-$1"
  echo "created 3 x $MACHINE ($1). They bill until you run: scripts/gcp_bench.sh down $1"
}

cmd_deploy() {
  check_profile "$1"
  local i tmp
  tmp=$(mktemp -d)
  git archive --format=tar.gz -o "$tmp/darkmpc.tgz" HEAD
  echo "deploying commit $(git rev-parse --short HEAD) (uncommitted changes are NOT included)"
  # First contact one VM at a time, so gcloud sets up SSH keys without racing.
  # A freshly created VM refuses SSH until it has booted, so retry for ~3 minutes.
  local t
  for i in 0 1 2; do
    for t in $(seq 1 36); do
      ssh_vm "$1" $i true >/dev/null 2>&1 && break
      [ "$t" -eq 36 ] && die "cannot SSH into $(name_of "$1" $i) after 3 minutes"
      echo "waiting for $(name_of "$1" $i) to accept SSH..."
      sleep 5
    done
  done
  for i in 0 1 2; do
    (
      ssh_vm "$1" $i 'for t in $(seq 1 30); do
          sudo apt-get -qq update && sudo apt-get -qq install -y build-essential curl iperf3 iputils-ping >/dev/null && break
          sleep 10   # the image may still be running its own first-boot apt
        done
        command -v iperf3 >/dev/null || exit 1
        [ -x "$HOME/.cargo/bin/cargo" ] || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null'
      scp_file_to "$1" $i "$tmp/darkmpc.tgz" darkmpc.tgz
      ssh_vm "$1" $i 'rm -rf darkmpc && mkdir darkmpc && tar -xzf darkmpc.tgz -C darkmpc && cd darkmpc &&
        $HOME/.cargo/bin/cargo build -q --release -p darkmpc-server && echo "built on $(hostname)"'
    ) &
    PIDS+=($!)
  done
  wait_all "deploying failed on at least one VM"
  rm -rf "$tmp"
}

cmd_net() {
  check_profile "$1"
  load_ips "$1"
  local out="$RESULTS/net-$1.txt" i j
  : > "$out"
  for i in 0 1 2; do
    j=$(( (i + 1) % 3 ))
    local rtt
    rtt=$(ssh_vm "$1" $i "ping -c 20 -i 0.2 -q ${IPS[$j]} | tail -1") \
      || die "VM $i cannot reach VM $j at ${IPS[$j]} (firewall?)"
    echo "rtt $i->$j: $rtt" | tee -a "$out"
  done
  ssh_vm "$1" 1 "pkill iperf3 || true; iperf3 -s -1 -D"
  sleep 1
  ssh_vm "$1" 0 "iperf3 -c ${IPS[1]} -t 5 -f m | grep -E 'sender|receiver'" | tee -a "$out"
}

# One auction. Prints one result line and appends it to the results file.
run_once() { # PROFILE N STAGE MODE REP
  local p=$1 n=$2 stage=$3 mode=$4 rep=$5 i
  local flags="" deal_flags=""
  [ "$stage" = 2 ] && { flags="--stage2"; deal_flags="--stage2"; }
  [ "$mode" = malicious ] && flags="$flags --malicious"
  local bin=target/release/darkmpc-server
  local dir; dir=$(mktemp -d)
  $bin setup --dir "$dir/deal" >/dev/null
  $bin deal --dir "$dir/deal" --orders "$n" $deal_flags >/dev/null
  load_ips "$p"
  local addrs="${IPS[0]}:$PORT,${IPS[1]}:$PORT,${IPS[2]}:$PORT"
  for i in 0 1 2; do
    ( ssh_vm "$p" $i "rm -rf bench" >/dev/null && scp_dir_to "$p" $i "$dir/deal" bench >/dev/null ) &
    PIDS+=($!)
  done
  wait_all "copying the deal to the VMs failed"
  for i in 0 1 2; do
    ssh_vm "$p" $i "cd bench && ../darkmpc/target/release/darkmpc-server run --dir . --id $i --addrs $addrs --passes 3 $flags > run.log 2>&1" &
    PIDS+=($!)
  done
  wait_all "a server failed (see ~/bench/run.log on the VMs)"
  for i in 0 1 2; do
    scp_from "$p" $i "bench/fills$i.bin" "$dir/deal/" >/dev/null
    scp_from "$p" $i "bench/stats$i.txt" "$dir/deal/" >/dev/null
  done
  local chk
  chk=$($bin check --dir "$dir/deal" --passes 3 $deal_flags) || { echo "$chk"; die "result does NOT match the reference"; }
  # Slowest server's auction time; rounds; the largest bytes sent by one server.
  local secs rounds bytes
  secs=$(echo "$chk" | sed -n 's/.*auction_secs=\([0-9.]*\).*/\1/p' | sort -g | tail -1)
  rounds=$(echo "$chk" | sed -n 's/.*rounds=\([0-9]*\).*/\1/p' | head -1)
  bytes=$(echo "$chk" | sed -n 's/.*bytes_sent=\([0-9]*\).*/\1/p' | sort -g | tail -1)
  local line="profile=$p machine=$(machine_of "$p") n=$n stage=$stage mode=$mode rep=$rep rounds=$rounds max_bytes=$bytes secs=$secs commit=$(git rev-parse --short HEAD)"
  echo "$line" | tee -a "$RESULTS/runs.txt"
  rm -rf "$dir"
}

cmd_run() {
  check_profile "$1"
  local reps=${5:-3} r
  cargo build -q --release -p darkmpc-server
  for r in $(seq 1 "$reps"); do run_once "$1" "$2" "$3" "$4" "$r"; done
}

cmd_grid() {
  check_profile "$1"
  local n s
  for s in 1 2; do
    for n in $GRID_SIZES; do cmd_run "$1" "$n" "$s" semi 3; done
    for n in $GRID_MAL_SIZES; do cmd_run "$1" "$n" "$s" malicious 3; done
  done
  cmd_summary
}

cmd_summary() {
  [ -f "$RESULTS/runs.txt" ] || die "no results yet"
  awk '
    { for (i=1;i<=NF;i++) { split($i,kv,"="); v[kv[1]]=kv[2] }
      k=v["profile"]" "v["n"]" "v["stage"]" "v["mode"]; t[k]=t[k]" "v["secs"]; r[k]=v["rounds"]; b[k]=v["max_bytes"] }
    END {
      for (k in t) {
        m=split(substr(t[k],2), a, " ")
        for (i=1;i<=m;i++) for (j=i+1;j<=m;j++) if (a[j]+0<a[i]+0) { x=a[i]; a[i]=a[j]; a[j]=x }
        med = (m%2) ? a[(m+1)/2] : (a[m/2]+a[m/2+1])/2
        split(k, f, " ")
        printf "%-4s %7d %5s %-9s %6d %12.1f %10.3f %6d\n", f[1], f[2], f[3], f[4], r[k], b[k]/1e6, med, m
      }
    }' "$RESULTS/runs.txt" | sort -k1,1 -k3,3 -k4,4 -k2,2n > "$RESULTS/.summary"
  printf "%-4s %7s %5s %-9s %6s %12s %10s %6s\n" net orders stage mode rounds MB/server "median s" runs
  cat "$RESULTS/.summary"
  rm -f "$RESULTS/.summary"
}

cmd_down() { # deletes whichever of the 3 VMs exist; never stops early
  check_profile "$1"
  local i name zone
  for i in 0 1 2; do
    name=$(name_of "$1" $i); zone=$(zone_of "$1" $i)
    if gcloud compute instances describe "$name" --zone "$zone" --format='get(name)' >/dev/null 2>&1; then
      gcloud compute instances delete "$name" --zone "$zone" --quiet &
      PIDS+=($!)
    fi
  done
  for i in ${PIDS[@]+"${PIDS[@]}"}; do wait "$i" || echo "warning: a delete failed" >&2; done
  PIDS=()
  rm -f "$RESULTS/ips-$1"
  echo "darkmpc VMs still existing (should be none for $1):"
  cmd_status
}

cmd_status() {
  gcloud compute instances list --filter="labels.darkmpc=bench" --format="table(name,zone.basename(),status)"
}

case "${1:-}" in
  quota) cmd_quota "${2:-}" ;;
  up) cmd_up "${2:-}" ;;
  deploy) cmd_deploy "${2:-}" ;;
  net) cmd_net "${2:-}" ;;
  run) [ $# -ge 5 ] || die "usage: run PROFILE N STAGE MODE [REPS]"; cmd_run "$2" "$3" "$4" "$5" "${6:-3}" ;;
  grid) cmd_grid "${2:-}" ;;
  summary) cmd_summary ;;
  down) cmd_down "${2:-}" ;;
  status) cmd_status ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
