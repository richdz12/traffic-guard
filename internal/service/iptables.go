package service

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	chainName = "SCANNERS-BLOCK"
)

// IptablesService handles iptables/ip6tables operations
type IptablesService struct {
	logger        zerolog.Logger
	enableLogging bool
	cmdSvc        *CommandService
	iptablesCmd   *IptablesCommandService
}

// NewIptablesService creates a new iptables service
func NewIptablesService(logger zerolog.Logger, cmdSvc *CommandService, enableLogging bool) *IptablesService {
	return &IptablesService{
		logger:        logger,
		enableLogging: enableLogging,
		cmdSvc:        cmdSvc,
		iptablesCmd:   NewIptablesCommandService(logger, cmdSvc),
	}
}

// SetupChain creates and configures iptables chains
func (s *IptablesService) SetupChain() error {
	s.logger.Info().Msg("Настройка цепочек iptables")

	// Check if UFW is active - if so, skip linking to INPUT
	// (rules will be added via ufw-before-input instead)
	linkToInput := !s.isUFWActive()
	if !linkToInput {
		s.logger.Info().Msg("UFW обнаружен - правила будут добавлены в ufw-before-input")
	}

	// Setup IPv4
	if err := s.setupIPv4Chain(linkToInput); err != nil {
		return fmt.Errorf("failed to setup IPv4 chain: %w", err)
	}

	// Setup IPv6
	if err := s.setupIPv6Chain(linkToInput); err != nil {
		return fmt.Errorf("failed to setup IPv6 chain: %w", err)
	}

	s.logger.Info().Msg("Цепочки iptables настроены")
	return nil
}

// setupIPv4Chain configures IPv4 chain
func (s *IptablesService) setupIPv4Chain(linkToInput bool) error {
	s.logger.Debug().Msg("Настройка IPv4 цепочки")

	// Check if chain exists
	if s.iptablesCmd.ChainExists(IPv4, TableFilter, chainName) {
		s.logger.Info().Str("chain", chainName).Msg("Очистка существующей цепочки iptables")
		if err := s.iptablesCmd.FlushChain(IPv4, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}
	} else {
		s.logger.Info().Str("chain", chainName).Msg("Создание цепочки iptables")
		if err := s.iptablesCmd.CreateChain(IPv4, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	// Link chain to INPUT (only if not using UFW)
	if linkToInput {
		if !s.iptablesCmd.RuleExists(IPv4, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Info().Msg("Привязка цепочки к INPUT")
			if err := s.iptablesCmd.LinkChainToInput(IPv4, chainName, 1); err != nil {
				return fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
		}
	}

	// Add logging rule if enabled
	if s.enableLogging {
		logRule := NewRuleBuilder().
			MatchSet(ipsetV4Name, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix("ANTISCAN-v4: ").
			LogLevel("4").
			Build()
		if !s.iptablesCmd.RuleExists(IPv4, TableFilter, chainName, logRule) {
			s.logger.Info().Msg("Добавление правила логирования IPv4")
			if err := s.iptablesCmd.InsertRule(IPv4, TableFilter, chainName, 1, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	// Add DROP rule
	dropRule := NewRuleBuilder().MatchSet(ipsetV4Name, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(IPv4, TableFilter, chainName, dropRule) {
		s.logger.Info().Msg("Добавление правила блокировки IPv4")
		if err := s.iptablesCmd.AppendRule(IPv4, TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// setupIPv6Chain configures IPv6 chain
func (s *IptablesService) setupIPv6Chain(linkToInput bool) error {
	s.logger.Debug().Msg("Настройка IPv6 цепочки")

	// Check if chain exists
	if s.iptablesCmd.ChainExists(IPv6, TableFilter, chainName) {
		s.logger.Info().Str("chain", chainName).Msg("Очистка существующей цепочки ip6tables")
		if err := s.iptablesCmd.FlushChain(IPv6, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}
	} else {
		s.logger.Info().Str("chain", chainName).Msg("Создание цепочки ip6tables")
		if err := s.iptablesCmd.CreateChain(IPv6, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	// Link chain to INPUT (only if not using UFW)
	if linkToInput {
		if !s.iptablesCmd.RuleExists(IPv6, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Info().Msg("Привязка цепочки к INPUT")
			if err := s.iptablesCmd.LinkChainToInput(IPv6, chainName, 1); err != nil {
				return fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
		}
	}

	// Add logging rule if enabled
	if s.enableLogging {
		logRule := NewRuleBuilder().
			MatchSet(ipsetV6Name, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix("ANTISCAN-v6: ").
			LogLevel("4").
			Build()
		if !s.iptablesCmd.RuleExists(IPv6, TableFilter, chainName, logRule) {
			s.logger.Info().Msg("Добавление правила логирования IPv6")
			if err := s.iptablesCmd.InsertRule(IPv6, TableFilter, chainName, 1, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	// Add DROP rule
	dropRule := NewRuleBuilder().MatchSet(ipsetV6Name, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(IPv6, TableFilter, chainName, dropRule) {
		s.logger.Info().Msg("Добавление правила блокировки IPv6")
		if err := s.iptablesCmd.AppendRule(IPv6, TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// Save saves iptables rules using appropriate method
func (s *IptablesService) Save() error {
	s.logger.Info().Msg("Сохранение правил iptables")

	// Check if UFW is installed (active or not) - integrate with it
	if s.cmdSvc.CommandExists("ufw") {
		s.logger.Info().Msg("UFW обнаружен - интеграция с UFW")
		return s.saveWithUFW()
	}

	// Use netfilter-persistent (should be installed by installer)
	if !s.cmdSvc.CommandExists("netfilter-persistent") {
		return fmt.Errorf("netfilter-persistent не установлен. Запустите установку зависимостей")
	}

	s.logger.Info().Msg("Использование netfilter-persistent")
	return s.saveWithNetfilterPersistent()
}

// isUFWActive checks if UFW is installed and active
func (s *IptablesService) isUFWActive() bool {
	if !s.cmdSvc.CommandExists("ufw") {
		return false
	}

	output, err := s.cmdSvc.RunOutput("ufw", "status")
	if err != nil {
		return false
	}

	return strings.Contains(output, "Status: active")
}

// saveWithUFW integrates rules with UFW
func (s *IptablesService) saveWithUFW() error {
	// CRITICAL: Check if SSH is allowed before enabling UFW
	// This prevents lockout when UFW is installed but inactive
	wasActive := s.isUFWActive()
	if !wasActive {
		s.logger.Warn().Msg("⚠️  UFW установлен но неактивен - проверка правил SSH перед включением")

		// Check if SSH rule exists in UFW config (user.rules or user6.rules)
		hasSSH := false

		// Check user.rules
		if content, err := os.ReadFile("/etc/ufw/user.rules"); err == nil {
			rules := string(content)
			if strings.Contains(rules, "dport 22") || strings.Contains(rules, "dport ssh") {
				hasSSH = true
			}
		}

		// Check user6.rules
		if !hasSSH {
			if content, err := os.ReadFile("/etc/ufw/user6.rules"); err == nil {
				rules := string(content)
				if strings.Contains(rules, "dport 22") || strings.Contains(rules, "dport ssh") {
					hasSSH = true
				}
			}
		}

		// Also check via ufw status if UFW can be queried
		if !hasSSH {
			if output, err := s.cmdSvc.RunOutput("ufw", "show", "added"); err == nil {
				if strings.Contains(output, "22/tcp") || strings.Contains(output, "22") || strings.Contains(output, "OpenSSH") || strings.Contains(output, "ssh") {
					hasSSH = true
				}
			}
		}

		if !hasSSH {
			s.logger.Error().Msg("╔════════════════════════════════════════════════════════════╗")
			s.logger.Error().Msg("║  ⚠️  КРИТИЧЕСКАЯ ОШИБКА - ПРЕДОТВРАЩЕНИЕ БЛОКИРОВКИ  ⚠️    ║")
			s.logger.Error().Msg("╚════════════════════════════════════════════════════════════╝")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("UFW установлен но НЕ имеет правил для SSH!")
			s.logger.Error().Msg("Включение UFW БЕЗ правил SSH ЗАБЛОКИРУЕТ удалённый доступ к серверу!")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("═══ ШАГ 1: Разрешите SSH в UFW ═══")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("Выполните ОДНУ из команд:")
			s.logger.Error().Msg("  sudo ufw allow 22/tcp     # Разрешить TCP порт 22")
			s.logger.Error().Msg("  sudo ufw allow OpenSSH    # Разрешить OpenSSH (рекомендуется)")
			s.logger.Error().Msg("  sudo ufw allow ssh        # Разрешить SSH сервис")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("Проверьте правило:")
			s.logger.Error().Msg("  sudo ufw show added")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("═══ ШАГ 2: Повторите установку antiscan ═══")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("  sudo antiscan apply -i /path/to/config")
			s.logger.Error().Msg("  # или")
			s.logger.Error().Msg("  sudo antiscan full")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("═══ АЛЬТЕРНАТИВА: Удалить UFW ═══")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("Если UFW не нужен:")
			s.logger.Error().Msg("  sudo apt remove --purge ufw")
			s.logger.Error().Msg("")
			s.logger.Error().Msg("antiscan будет работать с iptables напрямую")
			s.logger.Error().Msg("")
			return fmt.Errorf("SSH not allowed in UFW - installation aborted to prevent server lockout")
		}

		s.logger.Info().Msg("✓ Правило SSH найдено в конфигурации UFW")
	}

	// UFW сохраняет правила автоматически
	// Нужно только добавить наши правила в before.rules

	beforeRulesV4 := "/etc/ufw/before.rules"
	beforeRulesV6 := "/etc/ufw/before6.rules"

	// Читаем текущие before.rules
	contentV4, err := os.ReadFile(beforeRulesV4)
	if err != nil {
		return fmt.Errorf("failed to read UFW before.rules: %w", err)
	}

	contentV6, err := os.ReadFile(beforeRulesV6)
	if err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось прочитать UFW before6.rules")
	}

	// Проверяем есть ли уже наша цепочка
	markerV4 := "# SCANNERS-BLOCK chain - managed by antiscan"
	markerV6 := "# SCANNERS-BLOCK chain - managed by antiscan"

	if !strings.Contains(string(contentV4), markerV4) {
		// Добавляем наши правила в before.rules (внутри существующей секции *filter)
		// Включаем правила с ipset для LOG и DROP
		logRuleV4 := ""
		if s.enableLogging {
			logRuleV4 = fmt.Sprintf("-A %s -m set --match-set %s src -m limit --limit 10/min --limit-burst 5 -j LOG --log-prefix \"ANTISCAN-v4: \" --log-level 4\n", chainName, ipsetV4Name)
		}

		rulesV4 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
# DO NOT EDIT THIS SECTION MANUALLY
:%s - [0:0]
-A ufw-before-input -j %s
%s-A %s -m set --match-set %s src -j DROP
# END SCANNERS-BLOCK

`, chainName, chainName, logRuleV4, chainName, ipsetV4Name)

		// Вставляем перед последним COMMIT в конце *filter секции
		lastCommit := strings.LastIndex(string(contentV4), "COMMIT\n")
		if lastCommit == -1 {
			return fmt.Errorf("no COMMIT found in before.rules")
		}
		newContent := string(contentV4)[:lastCommit] + rulesV4 + string(contentV4)[lastCommit:]
		if err := os.WriteFile(beforeRulesV4+".new", []byte(newContent), 0640); err != nil {
			return fmt.Errorf("failed to write UFW rules: %w", err)
		}
		if err := os.Rename(beforeRulesV4+".new", beforeRulesV4); err != nil {
			return fmt.Errorf("failed to update UFW rules: %w", err)
		}
		s.logger.Info().Msg("Обновлён UFW before.rules для IPv4")
	}

	if contentV6 != nil && !strings.Contains(string(contentV6), markerV6) {
		logRuleV6 := ""
		if s.enableLogging {
			logRuleV6 = fmt.Sprintf("-A %s -m set --match-set %s src -m limit --limit 10/min --limit-burst 5 -j LOG --log-prefix \"ANTISCAN-v6: \" --log-level 4\n", chainName, ipsetV6Name)
		}

		rulesV6 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
:%s - [0:0]
-A ufw6-before-input -j %s
%s-A %s -m set --match-set %s src -j DROP
# END SCANNERS-BLOCK

`, chainName, chainName, logRuleV6, chainName, ipsetV6Name)

		lastCommit := strings.LastIndex(string(contentV6), "COMMIT\n")
		if lastCommit == -1 {
			s.logger.Warn().Msg("COMMIT не найден в before6.rules")
		} else {
			newContent := string(contentV6)[:lastCommit] + rulesV6 + string(contentV6)[lastCommit:]
			if err := os.WriteFile(beforeRulesV6+".new", []byte(newContent), 0640); err != nil {
				s.logger.Warn().Err(err).Msg("Не удалось записать UFW правила для IPv6")
			} else {
				if err := os.Rename(beforeRulesV6+".new", beforeRulesV6); err != nil {
					s.logger.Warn().Err(err).Msg("Не удалось обновить UFW правила для IPv6")
				} else {
					s.logger.Info().Msg("Обновлён UFW before6.rules для IPv6")
				}
			}
		}
	}

	// Перезагружаем UFW (используем disable+enable так как reload не всегда работает)
	// UFW загрузит правила из before.rules автоматически
	if !wasActive {
		s.logger.Warn().Msg("⚠️  UFW был неактивен - включаем его сейчас (SSH проверен)")
	}
	s.logger.Info().Msg("Перезапуск UFW для применения правил из before.rules")
	if err := s.cmdSvc.Run("ufw", "--force", "disable"); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось отключить UFW")
	}
	if err := s.cmdSvc.Run("ufw", "--force", "enable"); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить UFW")
	}
	if !wasActive {
		s.logger.Info().Msg("✓ UFW успешно активирован с правилами SSH")
	}

	// Перемещаем SCANNERS-BLOCK в начало ufw-before-input (позиция 1)
	// Это необходимо чтобы блокировка срабатывала ДО правил ACCEPT для ICMP и ESTABLISHED
	s.logger.Info().Msg("Перемещение SCANNERS-BLOCK на позицию 1 в ufw-before-input")

	// Удаляем правило из текущей позиции (оно добавлено из before.rules)
	if err := s.cmdSvc.Run("iptables", "-D", "ufw-before-input", "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось удалить SCANNERS-BLOCK из ufw-before-input")
	}

	// Вставляем в позицию 1 (самое начало)
	if err := s.cmdSvc.Run("iptables", "-I", "ufw-before-input", "1", "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось вставить SCANNERS-BLOCK на позицию 1 (IPv4)")
	} else {
		s.logger.Info().Msg("SCANNERS-BLOCK перемещён на позицию 1 в ufw-before-input (IPv4)")
	}

	// То же самое для IPv6
	if err := s.cmdSvc.Run("ip6tables", "-D", "ufw6-before-input", "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось удалить SCANNERS-BLOCK из ufw6-before-input")
	}

	if err := s.cmdSvc.Run("ip6tables", "-I", "ufw6-before-input", "1", "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось вставить SCANNERS-BLOCK на позицию 1 (IPv6)")
	} else {
		s.logger.Info().Msg("SCANNERS-BLOCK перемещён на позицию 1 в ufw6-before-input (IPv6)")
	}

	// Create systemd service to move rules after UFW starts
	if err := s.createMoveRuleService(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось создать systemd сервис для перемещения правил")
	}

	s.logger.Info().Msg("Правила iptables интегрированы с UFW")
	return nil
}

// createMoveRuleService creates systemd service to move SCANNERS-BLOCK to position 1 after UFW starts
func (s *IptablesService) createMoveRuleService() error {
	s.logger.Info().Msg("Создание systemd сервиса для поддержания SCANNERS-BLOCK на позиции 1")

	if err := os.WriteFile(MoveRulesServicePath, []byte(MoveRulesServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", MoveRulesServicePath).Msg("Создан systemd сервис")

	// Reload systemd daemon
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить systemd daemon")
	}

	// Enable service
	if err := s.cmdSvc.EnableService("antiscan-move-rules.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("Systemd сервис включён - SCANNERS-BLOCK будет на позиции 1 после перезагрузки")

	return nil
}

// saveWithNetfilterPersistent saves using netfilter-persistent
func (s *IptablesService) saveWithNetfilterPersistent() error {
	// Создаем директорию если не существует
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IPv4, "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Info().Msg("Правила IPv4 сохранены в /etc/iptables/rules.v4")

	if err := s.iptablesCmd.Save(IPv6, "/etc/iptables/rules.v6"); err != nil {
		return fmt.Errorf("failed to save ip6tables: %w", err)
	}
	s.logger.Info().Msg("Правила IPv6 сохранены в /etc/iptables/rules.v6")

	// Применяем через netfilter-persistent
	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
	}

	return nil
}
