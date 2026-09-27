#import "template.typ": *

#import "@preview/algorithmic:1.0.7"
#import algorithmic: algorithm-figure, style-algorithm
#show: style-algorithm

#show: template
// #set page(columns: 2)

#page([
  #title("Relatório")
  - Daniel Wesley Freitas Siqueira GRR20245621
  - Gabriel Gioia de Brito GRR20235159
])

= Algoritmos

Os algoritmos desenvolvidos para a criptografia foram feitos com paralelismo de operações em mente.

Cada iteração do algoritmo trabalha sobre blocos de `512b`, e cada bloco é considerado como 4 números de `128b`.

#algorithm-figure(
  "Encryption",
  vstroke: .5pt + luma(200),
  {
    import algorithmic: *
    Procedure(
      "DGENC_Encrypt",
      ("text", "key", "result"),
      {
        // Comment[Initialize the search range]
        Assign($"mask"$, FnInline[generateMask][$"key"$])
        Assign($"reduced_mask"$, FnInline[reduceAdd][$"key"$])
        LineBreak
        For(
          $i arrow.l 0 "to" "text.len" - 1$,
          {
            Assign($"xored"$, $"block" xor "mask"$)
            Assign($"reduced"$, FnInline[reduceAdd][xored])
            Assign($"red_xor_mask"$, $"reduced" xor "reduced_mask"$)
            Assign($"rem"$, $"red_xor_mask" bold(mod) 4$)
            Assign($"result[i][0]"$, $"xored[rem" bold(mod) 4]$)
            Assign($"result[i][1]"$, $"xored[(rem + 1)" bold(mod) 4]$)
            Assign($"result[i][2]"$, $"xored[(rem + 2)" bold(mod) 4]$)
            Assign($"result[i][3]"$, $"xored[(rem + 3)" bold(mod) 4]$)
          },
        )
      },
    )
  },
)

#algorithm-figure(
  "Decryption",
  vstroke: .5pt + luma(200),
  {
    import algorithmic: *
    Procedure(
      "DGENC_Decrypt",
      ("text", "key", "result"),
      {
        // Comment[Initialize the search range]
        Assign($"mask"$, FnInline[generateMask][$"key"$])
        Assign($"reduced_mask"$, FnInline[reduceAdd][$"key"$])
        LineBreak
        For(
          $i arrow.l 0 "to" "text.len" - 1$,
          {
            Assign($"xored"$, $"block" xor "mask"$)
            Assign($"reduced"$, FnInline[reduceAdd][xored])
            Assign($"red_xor_mask"$, $"reduced" xor "reduced_mask"$)
            Assign($"rem"$, $"red_xor_mask" bold(mod) 4$)
            Assign($"result[i][0]"$, $"xored[rem" bold(mod) 4]$)
            Assign($"result[i][1]"$, $"xored[(rem + 1)" bold(mod) 4]$)
            Assign($"result[i][2]"$, $"xored[(rem + 2)" bold(mod) 4]$)
            Assign($"result[i][3]"$, $"xored[(rem + 3)" bold(mod) 4]$)
          },
        )
      },
    )
  },
)

- *generateKey* é um acúmulo sucessivo dos blocos de `512b` da chave com operações XOR.
- *reduceAdd* é um acúmulo sucessivo de blocos de `128b` com operações ADD.

Os algoritmos de cifra e decifra consideram que a mensagem tem um tamanho múltiplo do bloco com que eles trabalham.

= Implementação

Foram feitas duas implementações dos algoritmos: uma escrita em zig utilizando _builtins_ para otimizações com instruções vetoriais, e outra em C com _instrinsics_ de `AVX512` diretamente.

- A compilação do código em C foi feita com `zig cc -c -mavx512f -mavx512bw -O3 vectorized_dgenc.c -o vectorized_dgenc.o`
- A compilação do código em zig após a geração do arquivo objeto anterior foi feita com `zig build -DOptimize=ReleaseFast -Dcpu=native`.

= Execução

- Tempos de cifra e decifra foram avaliados separadamente
  1. 1 execução sem medições para evitar anomalias com cache
  2. Mediu-se o tempo de 30 execuções e o resultado foi a média aritmética

= Considerações

É esperado que a execução do algoritmo desenvolvido seja bastante eficiente, já que:
- realiza apenas operações rápidas para a CPU (ADD e XOR e resto mod 4) por laço de repetição,
- passa apenas uma vez pelos dados, o que evita cache misses
- tira proveito tira bastante proveito de paralelismo com instruções vetoriais (XOR e shuffle).

= Resultados



#figure(
  image("plots/bar_all_log.png", height: 30%),
)
#figure(
  image("./plots/bar_encrypt_no_aes_log.png", height: 30%),
)
#figure(
  image("./plots/bar_decrypt_no_aes_log.png", height: 30%),
)
#figure(
  image("./plots/bar_encrypt_no_rsa_linear.png", height: 30%),
)
#figure(
  image("./plots/bar_decrypt_no_rsa_linear.png", height: 30%),
)

= Especificações 

Os testes foram executados em uma máquina com as seguintes especificações:

```
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             48 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      12
  On-line CPU(s) list:       0-11
Vendor ID:                   AuthenticAMD
  Model name:                AMD Ryzen 5 8500G w/ Radeon 740M Graphics
    CPU family:              25
    Model:                   120
    Thread(s) per core:      2
    Core(s) per socket:      6
    Socket(s):               1
    Stepping:                0
    Microcode version:       0xa70800a
    Frequency boost:         enabled
    CPU(s) scaling MHz:      60%
    CPU max MHz:             5080,2632
    CPU min MHz:             414,7160
    BogoMIPS:                7087,07
    Flags:                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc re
                             p_good amd_lbr_v2 nopl xtopology nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c
                              rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc m
                             waitx cpuid_fault cpb cat_l3 cdp_l3 hw_pstate ssbd mba perfmon_v2 ibrs ibpb stibp ibrs_enhanced vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx51
                             2f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_m
                             bm_local user_shstk avx512_bf16 clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists paus
                             efilter pfthreshold avic vgif x2avic v_spec_ctrl vnmi avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq rdpi
                             d overflow_recov succor smca fsrm flush_l1d amd_lbr_pmc_freeze
Virtualization features:
  Virtualization:            AMD-V
Caches (sum of all):
  L1d:                       192 KiB (6 instances)
  L1i:                       192 KiB (6 instances)
  L2:                        6 MiB (6 instances)
  L3:                        16 MiB (1 instance)
NUMA:
  NUMA node(s):              1
  NUMA node0 CPU(s):         0-11
Vulnerabilities:
  Gather data sampling:      Not affected
  Ghostwrite:                Not affected
  Indirect target selection: Not affected
  Itlb multihit:             Not affected
  L1tf:                      Not affected
  Mds:                       Not affected
  Meltdown:                  Not affected
  Mmio stale data:           Not affected
  Old microcode:             Not affected
  Reg file data sampling:    Not affected
  Retbleed:                  Not affected
  Spec rstack overflow:      Mitigation; Safe RET
  Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; STIBP always-on; PBRSB-eIBRS Not affected; BHI Not affected
  Srbds:                     Not affected
  Tsa:                       Mitigation; Clear CPU buffers
  Tsx async abort:           Not affected
  Vmscape:                   Mitigation; IBPB before exit to userspace
```

```
Machine (15GB total)
  Package L#0
    NUMANode L#0 (P#0 15GB)
    L3 L#0 (16MB)
      L2 L#0 (1024KB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0
        PU L#0 (P#0)
        PU L#1 (P#6)
      L2 L#1 (1024KB) + L1d L#1 (32KB) + L1i L#1 (32KB) + Core L#1
        PU L#2 (P#1)
        PU L#3 (P#7)
      L2 L#2 (1024KB) + L1d L#2 (32KB) + L1i L#2 (32KB) + Core L#2
        PU L#4 (P#2)
        PU L#5 (P#8)
      L2 L#3 (1024KB) + L1d L#3 (32KB) + L1i L#3 (32KB) + Core L#3
        PU L#6 (P#3)
        PU L#7 (P#9)
      L2 L#4 (1024KB) + L1d L#4 (32KB) + L1i L#4 (32KB) + Core L#4
        PU L#8 (P#4)
        PU L#9 (P#10)
      L2 L#5 (1024KB) + L1d L#5 (32KB) + L1i L#5 (32KB) + Core L#5
        PU L#10 (P#5)
        PU L#11 (P#11)
  HostBridge
    PCIBridge
      PCI 01:00.0 (VGA)
    PCIBridge
      PCIBridge
        PCIBridge
          PCI 07:00.0 (Ethernet)
            Net "enp7s0"
        PCIBridge
          PCI 0c:00.0 (SATA)
            Block(Disk) "sdb"
            Block(Disk) "sda"
```
)
