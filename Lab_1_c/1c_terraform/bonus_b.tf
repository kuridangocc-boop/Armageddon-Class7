# ############################################
# # Bonus B - ALB (Public) -> Target Group (Private EC2) + TLS + WAF + Monitoring
# ############################################

# locals {
#   # Explanation: This is the roar address — where the galaxy finds your app.
#   armageddon_lab_fqdn = "${var.app_subdomain}.${var.domain_name}"
# }

# ############################################
# # Security Group: ALB
# ############################################

# # Explanation: The ALB SG is the blast shield — only allow what the Rebellion needs (80/443).
# resource "aws_security_group" "armageddon_lab_alb_sg01" {
#   name        = "${var.project_name}-alb-sg01"
#   description = "ALB security group"
#   vpc_id      = aws_vpc.armageddon_lab_vpc01.id

#   # TODO: students add inbound 80/443 from 0.0.0.0/0
#   # TODO: students set outbound to target group port (usually 80) to private targets

#   tags = {
#     Name = "${var.project_name}-alb-sg01"
#   }
# }

# # Explanation: Chewbacca only opens the hangar door — allow ALB -> EC2 on app port (e.g., 80).
# resource "aws_security_group_rule" "armageddon_lab_ec2_ingress_from_alb01" {
#   type                     = "ingress"
#   security_group_id        = aws_security_group.armageddon_lab_ec2_sg01.id
#   from_port                = 80
#   to_port                  = 80
#   protocol                 = "tcp"
#   source_security_group_id = aws_security_group.armageddon_lab_alb_sg01.id

#   # TODO: students ensure EC2 app listens on this port (or change to 8080, etc.)
# }

# ############################################
# # Application Load Balancer
# ############################################

# # Explanation: The ALB is your public customs checkpoint — it speaks TLS and forwards to private targets.
# resource "aws_lb" "armageddon_lab_alb01" {
#   name               = "${var.project_name}-alb01"
#   load_balancer_type = "application"
#   internal           = false

#   security_groups = [aws_security_group.armageddon_lab_alb_sg01.id]
#   subnets         = aws_subnet.armageddon_lab_public_subnets[*].id

#   # TODO: students can enable access logs to S3 as a stretch goal

#   tags = {
#     Name = "${var.project_name}-alb01"
#   }
# }

# ############################################
# # Target Group + Attachment
# ############################################

# # Explanation: Target groups are Chewbacca’s “who do I forward to?” list — private EC2 lives here.
# resource "aws_lb_target_group" "armageddon_lab_tg01" {
#   name     = "${var.project_name}-tg01"
#   port     = 80
#   protocol = "HTTP"
#   vpc_id   = aws_vpc.armageddon_lab_vpc01.id

#   # TODO: students set health check path to something real (e.g., /health)
#   health_check {
#     enabled             = true
#     interval            = 30
#     path                = "/"
#     port                = "traffic-port"
#     protocol            = "HTTP"
#     healthy_threshold   = 2
#     unhealthy_threshold = 2
#     timeout             = 5
#     matcher             = "200-399"
#   }

#   tags = {
#     Name = "${var.project_name}-tg01"
#   }
# }

# # Explanation: Chewbacca personally introduces the ALB to the private EC2 — “this is my friend, don’t shoot.”
# resource "aws_lb_target_group_attachment" "armageddon_lab_tg_attach01" {
#   target_group_arn = aws_lb_target_group.armageddon_lab_tg01.arn
#   target_id        = aws_instance.armageddon_lab_ec201_private_bonus.id
#   port             = 80

#   # TODO: students ensure EC2 security group allows inbound from ALB SG on this port (rule above)
# }

# ############################################
# # ACM Certificate (TLS) for app.chewbacca-growl.com
# ############################################

# # Explanation: TLS is the diplomatic passport — browsers trust you, and Chewbacca stops growling at plaintext.
# resource "aws_acm_certificate" "armageddon_lab_acm_cert01" {
#   domain_name       = local.armageddon_lab_fqdn
#   validation_method = var.certificate_validation_method

#   # TODO: students can add subject_alternative_names like var.domain_name if desired

#   tags = {
#     Name = "${var.project_name}-acm-cert01"
#   }
# }

# # Explanation: DNS validation records are the “prove you own the planet” ritual — Route53 makes this elegant.
# # TODO: students implement aws_route53_record(s) if they manage DNS in Route53.
# # resource "aws_route53_record" "chewbacca_acm_validation" { ... }

# # Explanation: Once validated, ACM becomes the “green checkmark” — until then, ALB HTTPS won’t work.
# resource "aws_acm_certificate_validation" "armageddon_lab_acm_validation01" {
#   certificate_arn = aws_acm_certificate.armageddon_lab_acm_cert01.arn

#   # TODO: if using DNS validation, students must pass validation_record_fqdns
#   # validation_record_fqdns = [aws_route53_record.chewbacca_acm_validation.fqdn]
# }

# ############################################
# # ALB Listeners: HTTP -> HTTPS redirect, HTTPS -> TG
# ############################################

# # Explanation: HTTP listener is the decoy airlock — it redirects everyone to the secure entrance.
# resource "aws_lb_listener" "armageddon_lab_http_listener01" {
#   load_balancer_arn = aws_lb.armageddon_lab_alb01.arn
#   port              = 80
#   protocol          = "HTTP"

#   default_action {
#     type = "redirect"
#     redirect {
#       port        = "443"
#       protocol    = "HTTPS"
#       status_code = "HTTP_301"
#     }
#   }
# }

# # Explanation: HTTPS listener is the real hangar bay — TLS terminates here, then traffic goes to private targets.
# resource "aws_lb_listener" "armageddon_lab_https_listener01" {
#   load_balancer_arn = aws_lb.armageddon_lab_alb01.arn
#   port              = 443
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
#   certificate_arn   = aws_acm_certificate_validation.armageddon_lab_acm_validation01.certificate_arn

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.armageddon_lab_tg01.arn
#   }

#   depends_on = [aws_acm_certificate_validation.armageddon_lab_acm_validation01]
# }

# ############################################
# # WAFv2 Web ACL (Basic managed rules)
# ############################################

# # Explanation: WAF is the shield generator — it blocks the cheap blaster fire before it hits your ALB.
# resource "aws_wafv2_web_acl" "armageddon_lab_waf01" {
#   count = var.enable_waf ? 1 : 0

#   name  = "${var.project_name}-waf01"
#   scope = "REGIONAL"

#   default_action {
#     allow {}
#   }

#   visibility_config {
#     cloudwatch_metrics_enabled = true
#     metric_name                = "${var.project_name}-waf01"
#     sampled_requests_enabled   = true
#   }

#   # Explanation: AWS managed rules are like hiring Rebel commandos — they’ve seen every trick.
#   rule {
#     name     = "AWSManagedRulesCommonRuleSet"
#     priority = 1

#     override_action {
#       none {}
#     }

#     statement {
#       managed_rule_group_statement {
#         name        = "AWSManagedRulesCommonRuleSet"
#         vendor_name = "AWS"
#       }
#     }

#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "${var.project_name}-waf-common"
#       sampled_requests_enabled   = true
#     }
#   }

#   tags = {
#     Name = "${var.project_name}-waf01"
#   }
# }

# # Explanation: Attach the shield generator to the customs checkpoint — ALB is now protected.
# resource "aws_wafv2_web_acl_association" "armageddon_lab_waf_assoc01" {
#   count = var.enable_waf ? 1 : 0

#   resource_arn = aws_lb.armageddon_lab_alb01.arn
#   web_acl_arn  = aws_wafv2_web_acl.armageddon_lab_waf01[0].arn
# }

# ############################################
# # CloudWatch Alarm: ALB 5xx -> SNS
# ############################################

# # Explanation: When the ALB starts throwing 5xx, that’s the Falcon coughing — page the on-call Wookiee.
# resource "aws_cloudwatch_metric_alarm" "armageddon_lab_alb_5xx_alarm01" {
#   alarm_name          = "${var.project_name}-alb-5xx-alarm01"
#   comparison_operator = "GreaterThanOrEqualToThreshold"
#   evaluation_periods  = var.alb_5xx_evaluation_periods
#   threshold           = var.alb_5xx_threshold
#   period              = var.alb_5xx_period_seconds
#   statistic           = "Sum"

#   namespace   = "AWS/ApplicationELB"
#   metric_name = "HTTPCode_ELB_5XX_Count"

#   dimensions = {
#     LoadBalancer = aws_lb.armageddon_lab_alb01.arn_suffix
#   }

#   alarm_actions = [aws_sns_topic.armageddon_lab_sns_topic01.arn]

#   tags = {
#     Name = "${var.project_name}-alb-5xx-alarm01"
#   }
# }

# ############################################
# # CloudWatch Dashboard (Skeleton)
# ############################################

# # Explanation: Dashboards are your cockpit HUD — Chewbacca wants dials, not vibes.
# resource "aws_cloudwatch_dashboard" "armageddon_lab_dashboard01" {
#   dashboard_name = "${var.project_name}-dashboard01"

#   # TODO: students can expand widgets; this is a minimal workable skeleton
#   dashboard_body = jsonencode({
#     widgets = [
#       {
#         type  = "metric"
#         x     = 0
#         y     = 0
#         width = 12
#         height = 6
#         properties = {
#           metrics = [
#             [ "AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.armageddon_lab_alb01.arn_suffix ],
#             [ ".", "HTTPCode_ELB_5XX_Count", ".", aws_lb.armageddon_lab_alb01.arn_suffix ]
#           ]
#           period = 300
#           stat   = "Sum"
#           region = var.aws_region
#           title  = "Armageddon_Lab ALB: Requests + 5XX"
#         }
#       },
#       {
#         type  = "metric"
#         x     = 12
#         y     = 0
#         width = 12
#         height = 6
#         properties = {
#           metrics = [
#             [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.armageddon_lab_alb01.arn_suffix ]
#           ]
#           period = 300
#           stat   = "Average"
#           region = var.aws_region
#           title  = "Armageddon_Lab ALB: Target Response Time"
#         }
#       }
#     ]
#   })
# }