# # Explanation: Outputs are the mission coordinates — where to point your browser and your blasters.
# output "chewbacca_alb_dns_name" {
#   value = aws_lb.chewbacca_alb01.dns_name
# }

# output "chewbacca_app_fqdn" {
#   value = "${var.app_subdomain}.${var.domain_name}"
# }

# output "chewbacca_target_group_arn" {
#   value = aws_lb_target_group.chewbacca_tg01.arn
# }

# output "chewbacca_acm_cert_arn" {
#   value = aws_acm_certificate.chewbacca_acm_cert01.arn
# }

# output "chewbacca_waf_arn" {
#   value = var.enable_waf ? aws_wafv2_web_acl.chewbacca_waf01[0].arn : null
# }

# output "chewbacca_dashboard_name" {
#   value = aws_cloudwatch_dashboard.chewbacca_dashboard01.dashboard_name
# }